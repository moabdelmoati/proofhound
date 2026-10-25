"""Extract the call chain from exported functions down to a SAST sink.

Given a repo, a source file, and a sink line number, we:
  1. Parse the file with tree-sitter and build a function call graph.
  2. Find what the module exports (module.exports.X, exports.X, etc.).
  3. BFS from each exported function toward the function that contains the sink.
  4. Return a formatted chain string for injection into the harness-generation prompt.

The chain converts "figure out which function to call" into "follow these steps",
which is a much easier task for a small model.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Node, Parser

from proofhound.core.models import Finding

_LANGUAGES: dict[str, Language] = {
    ".js":  Language(ts_js.language()),
    ".mjs": Language(ts_js.language()),
    ".cjs": Language(ts_js.language()),
    ".jsx": Language(ts_js.language()),
    ".ts":  Language(ts_ts.language_typescript()),
    ".tsx": Language(ts_ts.language_tsx()),
}

_FUNCTION_NODES = {
    "function_declaration", "generator_function_declaration",
    "function_expression", "generator_function",
    "arrow_function", "method_definition",
}

MAX_CHAIN_DEPTH = 4
MAX_FILES_TO_SEARCH = 20


# ── helpers ───────────────────────────────────────────────────────────────────

def _txt(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _parse(source: bytes, suffix: str) -> Node:
    lang = _LANGUAGES.get(suffix, _LANGUAGES[".js"])
    tree = Parser(lang).parse(source)
    return tree.root_node


def _func_name_from_node(node: Node) -> str:
    """Best-effort name for a function node (mirrors javascript.py logic)."""
    own = node.child_by_field_name("name")
    parent = node.parent
    if node.type == "method_definition":
        cls = parent.parent if parent is not None and parent.type == "class_body" else None
        cls_name = _txt(cls.child_by_field_name("name")) if cls is not None else ""
        return f"{cls_name}.{_txt(own)}" if cls_name else _txt(own)
    if own is not None:
        return _txt(own)
    if parent is None:
        return "<anonymous>"
    if parent.type == "variable_declarator":
        return _txt(parent.child_by_field_name("name"))
    if parent.type == "assignment_expression":
        return _txt(parent.child_by_field_name("left"))
    if parent.type == "pair":
        return _txt(parent.child_by_field_name("key"))
    return "<anonymous>"


# ── data structures ────────────────────────────────────────────────────────────

@dataclass
class FuncNode:
    name: str
    start_line: int
    end_line: int
    calls: list[str] = field(default_factory=list)   # callee names (bare)
    params: str = ""                                   # "(a, b, c)"
    exported_as: str | None = None                     # "module.exports.run" or None


@dataclass
class ChainStep:
    func_name: str
    call_expr: str    # how the caller invokes it: "run(input)" / "module.exports.run(input)"
    file: Path
    line: int


# ── AST walker ─────────────────────────────────────────────────────────────────

def _collect_functions(root: Node, source_lines: list[str]) -> list[FuncNode]:
    """Walk the AST and return one FuncNode per function definition."""
    nodes: list[FuncNode] = []

    def walk(n: Node) -> None:
        if n.type in _FUNCTION_NODES:
            name = _func_name_from_node(n)
            start = n.start_point.row + 1
            end = n.end_point.row + 1
            params_node = n.child_by_field_name("parameters")
            params = _txt(params_node) if params_node else "(data)"
            fn = FuncNode(name=name, start_line=start, end_line=end, params=params)
            nodes.append(fn)
        for child in n.children:
            walk(child)

    walk(root)
    return nodes


def _collect_calls_in_range(root: Node, start_line: int, end_line: int) -> list[str]:
    """Return bare callee names for all call_expression nodes in [start_line, end_line]."""
    results: list[str] = []

    def walk(n: Node) -> None:
        row = n.start_point.row + 1
        if row < start_line or row > end_line:
            for child in n.children:
                walk(child)
            return
        if n.type == "call_expression":
            fn_node = n.child_by_field_name("function")
            if fn_node:
                callee = _txt(fn_node)
                # Strip "this." and keep only the last segment for matching
                bare = callee.split(".")[-1] if "." in callee else callee
                if bare and bare not in {"require", "console", "JSON", "Math", "Object", "Array"}:
                    results.append(bare)
        for child in n.children:
            walk(child)

    walk(root)
    return results


# ── export detection ───────────────────────────────────────────────────────────

def _scan_exports_object(source: str) -> dict[str, str]:
    """Parse `module.exports = { key: val, ... }` with brace-level tracking.
    Returns {val: exported_as_key} for simple key:val pairs (no inline functions).
    """
    m = re.search(r"module\.exports\s*=\s*\{", source)
    if not m:
        return {}
    depth = 0
    start = m.end() - 1  # position of '{'
    end = start
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = source[start + 1:end]
    result: dict[str, str] = {}
    # Split on commas that are not inside nested braces/parens
    depth2, seg_start = 0, 0
    parts: list[str] = []
    for i, ch in enumerate(body):
        if ch in "({[":
            depth2 += 1
        elif ch in ")}]":
            depth2 -= 1
        elif ch == "," and depth2 == 0:
            parts.append(body[seg_start:i].strip())
            seg_start = i + 1
    parts.append(body[seg_start:].strip())
    for part in parts:
        if ":" not in part:
            # shorthand: { foo } → key=foo, val=foo
            key = part.strip()
            if re.fullmatch(r"\w+", key):
                result[key] = key
        else:
            colon = part.index(":")
            key = part[:colon].strip()
            val = part[colon + 1:].strip()
            # Only record simple identifier values (not inline functions/objects)
            if re.fullmatch(r"\w+", key) and re.fullmatch(r"\w+", val):
                result[val] = key
    return result


def _extract_exports(source: str, funcs: list[FuncNode]) -> dict[str, str]:
    """Map function name → export expression (e.g. 'module.exports.run').

    Handles the most common CJS patterns:
      module.exports = fn
      module.exports.fn = function(...) / arrow / fn
      exports.fn = ...
      module.exports = { fn1, fn2, fn3 }   ← now handles nested braces
    """
    exported: dict[str, str] = {}
    func_names = {f.name for f in funcs}

    for match in re.finditer(r"module\.exports\.(\w+)\s*=", source):
        name = match.group(1)
        if name in func_names:
            exported[name] = f"module.exports.{name}"

    for match in re.finditer(r"exports\.(\w+)\s*=", source):
        name = match.group(1)
        if name in func_names and name not in exported:
            exported[name] = f"exports.{name}"

    obj_pairs = _scan_exports_object(source)
    for val, key in obj_pairs.items():
        if val in func_names and val not in exported:
            exported[val] = f"module.exports.{key}"

    # module.exports = singleFn
    single = re.search(r"module\.exports\s*=\s*(\w+)\s*(?:;|$|\n)", source)
    if single:
        name = single.group(1)
        if name in func_names and name not in exported:
            exported[name] = "module.exports"

    return exported


def _find_method_owner(source: str, func_name: str, func_start_line: int) -> str | None:
    """If `func_name` appears as a method (`func_name: function`) at `func_start_line`
    inside a var-assigned IIFE, return the variable name. Handles:
      var Utils = (function() { return { remove: function(...) {...} }; })();
    Returns e.g. 'Utils'.
    """
    lines = source.splitlines()
    for m in re.finditer(rf"\b{re.escape(func_name)}\s*:\s*function\b", source):
        match_line = source[:m.start()].count("\n") + 1
        if abs(match_line - func_start_line) > 2:
            continue
        prefix = source[:m.start()]
        iife_matches = list(re.finditer(r"var\s+(\w+)\s*=\s*\(?\s*function", prefix))
        if iife_matches:
            return iife_matches[-1].group(1)
    return None


# ── cross-file search ─────────────────────────────────────────────────────────

def _find_js_files(repo: Path, exclude: Path, limit: int = MAX_FILES_TO_SEARCH) -> list[Path]:
    """JS/TS files in the repo, excluding node_modules and the sink file itself."""
    files: list[Path] = []
    for p in repo.rglob("*"):
        if len(files) >= limit:
            break
        if p.suffix not in _LANGUAGES:
            continue
        if "node_modules" in p.parts:
            continue
        if p.resolve() == exclude.resolve():
            continue
        files.append(p)
    return files


def _find_cross_file_callers(
    repo: Path,
    module_file: Path,
    export_expr: str,
    func_name: str,
) -> list[tuple[Path, str, int]]:
    """Search other repo files for calls to `func_name` or `export_expr`. Returns (file, call_text, line)."""
    results: list[tuple[Path, str, int]] = []
    patterns = [re.compile(rf"\b{re.escape(func_name)}\s*\(")]
    if export_expr and export_expr != func_name:
        patterns.append(re.compile(rf"{re.escape(export_expr)}\s*\("))

    for js_file in _find_js_files(repo, module_file):
        try:
            text = js_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat in patterns:
                if pat.search(line):
                    results.append((js_file, line.strip(), i))
                    break
        if results:
            break  # first caller file is enough
    return results


# ── main BFS chain builder ────────────────────────────────────────────────────

def _find_sink_func(funcs: list[FuncNode], sink_line: int) -> FuncNode | None:
    """The innermost *named* function that contains sink_line.

    Anonymous callbacks (e.g. exec(cmd, function(err) {...})) that happen to start
    on the sink line are useless for BFS — they're not callable from a harness.
    We prefer the innermost named parent function instead.
    """
    candidates = [f for f in funcs if f.start_line <= sink_line <= f.end_line]
    if not candidates:
        return None
    # Prefer named functions (smallest span), fall back to anonymous only if nothing named
    named = [f for f in candidates if f.name != "<anonymous>"]
    pool = named if named else candidates
    return min(pool, key=lambda f: f.end_line - f.start_line)


def _bfs_chain(
    funcs: list[FuncNode],
    exported: dict[str, str],
    sink_func_name: str,
) -> list[str] | None:
    """BFS from exported functions toward sink_func_name. Returns the chain of names, or None."""
    name_to_func = {f.name: f for f in funcs}
    # Build caller map: who calls whom
    caller_of: dict[str, list[str]] = {}  # callee → list[caller]
    for f in funcs:
        for callee in f.calls:
            caller_of.setdefault(callee, []).append(f.name)

    # If sink is directly exported, chain is trivial
    if sink_func_name in exported:
        return [sink_func_name]

    # BFS from sink upward toward exported functions
    queue: deque[list[str]] = deque([[sink_func_name]])
    seen: set[str] = {sink_func_name}
    while queue:
        path = queue.popleft()
        if len(path) > MAX_CHAIN_DEPTH:
            continue
        current = path[0]
        for caller in caller_of.get(current, []):
            if caller in seen:
                continue
            seen.add(caller)
            new_path = [caller] + path
            if caller in exported:
                return new_path
            queue.append(new_path)
    return None


# ── public API ────────────────────────────────────────────────────────────────

def extract_call_chain(repo: Path, finding: Finding) -> str:
    """Return a prompt-ready call chain string, or "" if nothing useful found."""
    if finding.function is None:
        return ""

    module_file = repo / finding.file
    if not module_file.is_file():
        return ""

    try:
        source_bytes = module_file.read_bytes()
        source_str = source_bytes.decode("utf-8", "replace")
    except OSError:
        return ""

    suffix = module_file.suffix
    root = _parse(source_bytes, suffix)
    source_lines = source_str.splitlines()

    funcs = _collect_functions(root, source_lines)
    for fn in funcs:
        fn.calls = _collect_calls_in_range(root, fn.start_line, fn.end_line)

    exported = _extract_exports(source_str, funcs)
    sink_func = _find_sink_func(funcs, finding.line)
    if sink_func is None:
        return ""

    chain_names = _bfs_chain(funcs, exported, sink_func.name)

    func_map = {f.name: f for f in funcs}
    lines: list[str] = [
        "## Call chain to reach the sink",
        f"The sink is at line {finding.line} inside `{sink_func.name}()`.",
        "To reach it from your harness entry point:",
        "",
    ]

    if chain_names is None:
        # Check if sink is a method of an exported object variable (IIFE pattern:
        # var Foo = (function() { return { sink_name: function(...){...} }; })()
        # and module.exports = { foo: Foo, ... })
        obj_exports = _scan_exports_object(source_str)  # val → key in exports object
        owner = _find_method_owner(source_str, sink_func.name, sink_func.start_line)
        if owner and owner in obj_exports:
            export_key = obj_exports[owner]
            sink_fn = func_map.get(sink_func.name)
            params = sink_fn.params if sink_fn else "(...)"
            lines += [
                f"  Step 1: `require(module).{export_key}` gives you the `{owner}` object.",
                f"  Step 2: call `require(module).{export_key}.{sink_func.name}{params}`"
                f"  [line {sink_func.start_line}]  ← contains the SINK",
            ]
            return "\n".join(lines)

        # No chain found inside the file — look for cross-file callers
        if exported:
            exported_name = next(iter(exported))
            export_expr = exported[exported_name]
            cross = _find_cross_file_callers(repo, module_file, export_expr, sink_func.name)
            if cross:
                cf_file, cf_call, cf_line = cross[0]
                lines += [
                    f"  `{sink_func.name}()` is called from `{cf_file.name}` (line {cf_line}).",
                    f"  The module exports: {', '.join(f'`{v}`' for v in exported.values())}",
                    f"  Start by requiring the module and calling an exported function.",
                ]
            else:
                lines += [
                    f"  `{sink_func.name}()` is not directly exported.",
                    f"  Module exports: {', '.join(f'`{v}`' for v in exported.values()) or 'unknown'}",
                    f"  Trace the source to find which exported function leads to `{sink_func.name}()`.",
                ]
        else:
            lines += [f"  No obvious exports found. Check `module.exports` in the full source."]
        return "\n".join(lines)

    # Format the chain
    for i, name in enumerate(chain_names):
        fn = func_map.get(name)
        prefix = "→ " * i
        if i == 0:
            export_expr = exported.get(name, f"module.exports.{name}")
            params = fn.params if fn else "(data)"
            lines.append(f"  Step 1: call `{export_expr}{params}`  ← start here (exported)")
        elif i == len(chain_names) - 1:
            line_no = fn.start_line if fn else "?"
            lines.append(f"  Step {i+1}: this calls `{name}()`  [line {line_no}]  ← contains the SINK")
        else:
            line_no = fn.start_line if fn else "?"
            lines.append(f"  Step {i+1}: which calls `{name}()`  [line {line_no}]")

    if len(chain_names) == 1:
        lines.append(f"  (the sink function is directly exported — call it straight from the harness)")

    return "\n".join(lines)
