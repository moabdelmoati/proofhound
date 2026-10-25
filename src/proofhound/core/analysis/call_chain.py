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
    param_names: list[str] = field(default_factory=list)
    arg_types: dict[str, str] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    exported_as: str | None = None                     # "module.exports.run" or None


@dataclass
class ChainStep:
    func_name: str
    call_expr: str    # how the caller invokes it: "run(input)" / "module.exports.run(input)"
    file: Path
    line: int
    arg_types: dict[str, str] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)


# ── AST walker ─────────────────────────────────────────────────────────────────

_ARRAY_METHODS = {
    "forEach", "map", "filter", "reduce", "slice", "push", "pop", "shift",
    "unshift", "concat", "join", "find", "findIndex", "some", "every", "splice",
}

_STRING_METHODS = {
    "trim", "split", "replace", "replaceAll", "toLowerCase", "toUpperCase",
    "substring", "substr", "charAt", "charCodeAt", "match", "search",
    "startsWith", "endsWith", "indexOf", "lastIndexOf", "includes",
}


def _extract_param_names(params_node: Node | None) -> list[str]:
    if not params_node:
        return []
    names = []
    for child in params_node.children:
        if child.type == "identifier":
            names.append(_txt(child))
        elif child.type == "assignment_pattern":
            left = child.child_by_field_name("left")
            if left and left.type == "identifier":
                names.append(_txt(left))
        elif child.type == "rest_pattern":
            for sub in child.children:
                if sub.type == "identifier":
                    names.append(_txt(sub))
                    break
        elif child.type in ("object_pattern", "array_pattern"):
            names.append(_txt(child))
    return [n for n in names if n and n not in ("(", ")", ",")]


def _infer_param_type(param: str, body_node: Node | None) -> str:
    if not body_node:
        return _infer_by_name(param)

    is_array = False
    is_function = False
    is_string = False
    is_number = False
    is_object = False

    def walk_usage(n: Node) -> None:
        nonlocal is_array, is_function, is_string, is_number, is_object

        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if fn:
                fn_txt = _txt(fn)
                if fn_txt == "Array.isArray" and args and param in _txt(args):
                    is_array = True
                elif fn_txt == param or fn_txt.endswith("." + param):
                    is_function = True
                elif fn.type == "member_expression":
                    obj = fn.child_by_field_name("object")
                    prop = fn.child_by_field_name("property")
                    if obj and _txt(obj) == param and prop:
                        prop_name = _txt(prop)
                        if prop_name in _ARRAY_METHODS:
                            is_array = True
                        elif prop_name in _STRING_METHODS:
                            is_string = True
                        else:
                            is_object = True

        if n.type in ("for_of_statement", "for_in_statement"):
            right = n.child_by_field_name("right")
            if right and _txt(right) == param:
                is_array = True

        if n.type == "template_substitution":
            if param in _txt(n):
                is_string = True

        if n.type == "binary_expression":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            op = _txt(n.child_by_field_name("operator"))
            txt_left, txt_right = _txt(left), _txt(right)

            if op == "+" and (txt_left == param or txt_right == param):
                if (left and left.type == "string") or (right and right.type == "string"):
                    is_string = True
                elif (left and left.type == "number") or (right and right.type == "number"):
                    is_number = True

            if op in ("==", "===", "!=", "!=="):
                sub_txt = _txt(n)
                if f"typeof {param}" in sub_txt or f"typeof({param})" in sub_txt:
                    if '"string"' in sub_txt or "'string'" in sub_txt:
                        is_string = True
                    elif '"number"' in sub_txt or "'number'" in sub_txt:
                        is_number = True
                    elif '"function"' in sub_txt or "'function'" in sub_txt:
                        is_function = True
                    elif '"object"' in sub_txt or "'object'" in sub_txt:
                        is_object = True

            if op in ("-", "*", "/", "%"):
                if txt_left == param or txt_right == param:
                    is_number = True

            if op in ("<", ">", "<=", ">="):
                if (txt_left == param and right and right.type == "number") or (
                    txt_right == param and left and left.type == "number"
                ):
                    is_number = True

            if op == "in" and txt_right == param:
                is_object = True

        if n.type == "member_expression":
            obj = n.child_by_field_name("object")
            prop = n.child_by_field_name("property")
            if obj and _txt(obj) == param and prop:
                prop_name = _txt(prop)
                if prop_name in _ARRAY_METHODS:
                    is_array = True
                elif prop_name in _STRING_METHODS:
                    is_string = True
                elif prop_name != "length":
                    is_object = True

        for child in n.children:
            walk_usage(child)

    walk_usage(body_node)

    if is_array:
        return "array"
    if is_function:
        return "function"
    if is_string:
        return "string"
    if is_number:
        return "number"
    if is_object:
        return "object"

    return _infer_by_name(param)


def _infer_by_name(name: str) -> str:
    n = name.lower()
    if n in ("cb", "callback", "fn", "done", "next", "resolve", "reject"):
        return "function"
    if any(k in n for k in ("opts", "options", "config", "settings", "params")):
        return "object"
    if any(k in n for k in ("arr", "list", "items", "lines", "files", "hosts")):
        return "array"
    if any(k in n for k in ("cmd", "command", "path", "file", "str", "name", "url", "ip", "host", "regex", "pattern", "dir")):
        return "string"
    if any(k in n for k in ("count", "timeout", "port", "len", "size", "index", "num")):
        return "number"
    return "unknown"


def _clean_precondition(cond: str) -> str:
    cond = cond.strip()
    if cond.startswith("(") and cond.endswith(")"):
        cond = cond[1:-1].strip()
    m = re.match(r"^!\s*\((.+)\)$", cond)
    if m:
        return m.group(1).strip()
    m = re.match(r"^!\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)$", cond)
    if m:
        return m.group(1).strip()
    cond = re.sub(
        r"typeof\s+([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*!==\s*('string'|\"string\")",
        r"typeof \1 === \2",
        cond,
    )
    return cond


def _extract_preconditions(body_node: Node | None) -> list[str]:
    if not body_node:
        return []
    preconds = []
    statements = [c for c in body_node.children if c.type not in ("{", "}")]
    for st in statements[:5]:
        if st.type == "if_statement":
            cond = st.child_by_field_name("condition")
            conseq = st.child_by_field_name("consequence")
            conseq_text = _txt(conseq)
            is_guard = any(k in conseq_text for k in ("return", "throw", "reject", "exit"))
            if cond and (is_guard or "assert" in _txt(st) or "typeof" in _txt(cond) or "isArray" in _txt(cond)):
                text = _clean_precondition(_txt(cond))
                if text and text not in preconds:
                    preconds.append(text)
        elif st.type == "expression_statement":
            txt = _txt(st).strip().rstrip(";")
            m = re.search(r"assert(?:\.\w+)?\((.*)\)", txt)
            if m:
                preconds.append(m.group(1).strip())
    return preconds


def _find_sink_call_on_line(root: Node, line: int) -> str | None:
    found: str | None = None

    def walk(n: Node) -> None:
        nonlocal found
        if n.start_point.row + 1 == line and n.type == "call_expression":
            fn_node = n.child_by_field_name("function")
            if fn_node:
                txt = _txt(fn_node).split(".")[-1]
                if txt not in {"require", "console"}:
                    found = txt
                    return
        for c in n.children:
            walk(c)

    walk(root)
    return found


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
            param_names = _extract_param_names(params_node)
            body_node = n.child_by_field_name("body")
            arg_types = {p: _infer_param_type(p, body_node) for p in param_names}
            preconditions = _extract_preconditions(body_node)
            fn = FuncNode(
                name=name, start_line=start, end_line=end, params=params,
                param_names=param_names, arg_types=arg_types, preconditions=preconditions,
            )
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

    # If sink is directly exported (or a method on an exported constructor/class), chain is trivial
    if sink_func_name in exported:
        return [sink_func_name]
    cls_name = sink_func_name.split(".")[0] if "." in sink_func_name else None
    if cls_name and cls_name in exported:
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
            caller_cls = caller.split(".")[0] if "." in caller else None
            if caller in exported or (caller_cls and caller_cls in exported):
                return new_path
            queue.append(new_path)
    return None


# ── public API ────────────────────────────────────────────────────────────────

def extract_call_chain(repo: Path, finding: Finding, v2: bool = True) -> str:
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

    if v2:
        sink_call = _find_sink_call_on_line(root, finding.line)
        if chain_names:
            v2_lines = ["Call chain:"]
            for i, name in enumerate(chain_names):
                fn = func_map.get(name)
                short_name = name.split(".")[-1] if "." in name else name
                if fn and fn.param_names:
                    args_str = ", ".join(f"{p}: {fn.arg_types.get(p, 'unknown')}" for p in fn.param_names)
                elif fn and fn.params:
                    args_str = fn.params.strip("()")
                else:
                    args_str = "data: unknown"
                step = f"  {i + 1}. {short_name}({args_str})"
                if fn and fn.preconditions:
                    step += f"  — precondition: {' && '.join(fn.preconditions)}"
                if i == len(chain_names) - 1:
                    if sink_call and sink_call != short_name:
                        v2_lines.append(step)
                        sink_args = "cmd: string, cb: function" if "exec" in sink_call else "args: unknown"
                        v2_lines.append(f"  {i + 2}. {sink_call}({sink_args})  — sink")
                        continue
                    else:
                        step += "  — sink"
                v2_lines.append(step)
            return "\n".join(v2_lines)

        owner = _find_method_owner(source_str, sink_func.name, sink_func.start_line)
        obj_exports = _scan_exports_object(source_str)
        if owner and owner in obj_exports:
            export_key = obj_exports[owner]
            fn = func_map.get(sink_func.name)
            short_name = sink_func.name.split(".")[-1]
            if fn and fn.param_names:
                args_str = ", ".join(f"{p}: {fn.arg_types.get(p, 'unknown')}" for p in fn.param_names)
            else:
                args_str = fn.params.strip("()") if fn and fn.params else "data: unknown"
            step1 = f"  1. require(module).{export_key} (provides {owner})"
            step2 = f"  2. {short_name}({args_str})"
            if fn and fn.preconditions:
                step2 += f"  — precondition: {' && '.join(fn.preconditions)}"
            if sink_call and sink_call != short_name:
                sink_args = "cmd: string, cb: function" if "exec" in sink_call else "args: unknown"
                step3 = f"  3. {sink_call}({sink_args})  — sink"
                return "\n".join(["Call chain:", step1, step2, step3])
            else:
                step2 += "  — sink"
                return "\n".join(["Call chain:", step1, step2])

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
