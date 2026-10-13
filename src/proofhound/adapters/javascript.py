"""JavaScript/TypeScript adapter (Jazzer.js). TypeScript compiles to JS, so one adapter serves both."""

import json
import re
from pathlib import Path

import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Node, Parser

from proofhound.adapters.base import FuzzerReport, LanguageAdapter
from proofhound.models import ChangedFunction
from proofhound.sandbox.docker_runner import OUT, TARGET

FUNCTION_NODES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
}

_LANGUAGES = {
    ".js": Language(ts_js.language()),
    ".mjs": Language(ts_js.language()),
    ".cjs": Language(ts_js.language()),
    ".jsx": Language(ts_js.language()),
    ".ts": Language(ts_ts.language_typescript()),
    ".tsx": Language(ts_ts.language_tsx()),
}

HARNESS_TEMPLATE = """\
const { FuzzedDataProvider } = require("@jazzer.js/core");
const target = require("{module}");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  // Build arguments from `provider` and call the target function.
  // Catch only errors the target throws for invalid input; never swallow bug-detector reports.
};
"""


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def function_name(node: Node) -> str:
    """Best-effort qualified name: `Class.method`, `module.exports.foo`, `obj.key`, or `<anonymous>`."""
    own = node.child_by_field_name("name")
    parent = node.parent
    if node.type == "method_definition":
        cls = parent.parent if parent is not None and parent.type == "class_body" else None
        cls_name = _text(cls.child_by_field_name("name")) if cls is not None else ""
        return f"{cls_name}.{_text(own)}" if cls_name else _text(own)
    if own is not None:
        return _text(own)
    if parent is None:
        return "<anonymous>"
    if parent.type == "variable_declarator":
        return _text(parent.child_by_field_name("name"))
    if parent.type == "assignment_expression":
        return _text(parent.child_by_field_name("left"))
    if parent.type == "pair":
        return _text(parent.child_by_field_name("key"))
    if parent.type == "export_statement":
        return "default"
    return "<anonymous>"


class JavaScriptAdapter(LanguageAdapter):
    name = "javascript"
    extensions = tuple(_LANGUAGES)
    fuzzer = "jazzer.js"
    sandbox_image = "proofhound/jazzerjs:latest"

    def functions(self, file: Path, source: bytes) -> list[ChangedFunction]:
        """Every function in the file, outermost first."""
        parser = Parser(_LANGUAGES[file.suffix])
        found: list[ChangedFunction] = []
        stack = [parser.parse(source).root_node]
        while stack:
            node = stack.pop()
            if node.type in FUNCTION_NODES:
                found.append(
                    ChangedFunction(
                        file=file,
                        name=function_name(node),
                        start_line=node.start_point.row + 1,
                        end_line=node.end_point.row + 1,
                        language=self.name,
                    )
                )
            stack.extend(reversed(node.children))
        return found

    def extract_functions(
        self, file: Path, changed_lines: set[int], root: Path = Path(".")
    ) -> list[ChangedFunction]:
        source = (root / file).read_bytes()
        return [
            fn for fn in self.functions(file, source)
            if any(fn.start_line <= line <= fn.end_line for line in changed_lines)
        ]

    def harness_template(self, module: str = TARGET) -> str:
        return HARNESS_TEMPLATE.replace("{module}", module)

    # Harnesses run in async mode (no --sync) so targets that return promises are awaited.
    def fuzz_command(self, time_s: int) -> list[str]:
        return [
            "jazzer", HARNESS, f"{OUT}/corpus",
            "--", f"-max_total_time={time_s}", f"-artifact_prefix={OUT}/",
        ]

    def replay_command(self, inputs: str) -> list[str]:
        return ["jazzer", HARNESS, f"{OUT}/{inputs}", "-m", "regression"]

    def coverage_command(self, inputs: str) -> list[str]:
        return [
            *self.replay_command(inputs),
            "--coverage", "--coverageDirectory", f"{OUT}/coverage", "--coverageReporters", "json",
        ]

    def function_hits(self, out: Path, fn: ChangedFunction) -> int | None:
        report = out / "coverage" / "coverage-final.json"
        if not report.exists():
            return None
        per_file = json.loads(report.read_text(encoding="utf-8")).get(f"{TARGET}/{fn.file.as_posix()}")
        if per_file is None:
            return 0  # the file was never loaded
        starts = {
            key: meta["decl"]["start"]["line"] for key, meta in per_file["fnMap"].items()
        }
        inside = [k for k, line in starts.items() if fn.start_line <= line <= fn.end_line]
        if not inside:
            return 0
        outermost = min(inside, key=lambda k: starts[k])
        return per_file["f"][outermost]

    def parse_reports(self, output: str) -> list[FuzzerReport]:
        return parse_jazzer_output(output)

    def target_frame(self, frames: list[str]) -> str | None:
        return first_target_frame(frames)


HARNESS = f"{OUT}/harness.js"
SECURITY_DETECTORS = {"Command Injection", "Path Traversal", "Prototype Pollution"}
_HEADER = re.compile(r"^==\d+== (.+)$")
_TIMEOUT = re.compile(r"ERROR: libFuzzer: timeout")
_FRAME = re.compile(r"^\s+at ")
_ARTIFACT = re.compile(r"Test unit written to (\S+)")


def parse_jazzer_output(output: str) -> list[FuzzerReport]:
    reports: list[FuzzerReport] = []
    current: FuzzerReport | None = None
    for line in output.splitlines():
        header = _HEADER.match(line)
        if header or _TIMEOUT.search(line):
            title = header.group(1).strip() if header else "Timeout"
            kind = "Uncaught Exception" if title.startswith("Uncaught Exception") else title
            current = FuzzerReport(kind, kind in SECURITY_DETECTORS, "", [], None)
            reports.append(current)
            continue
        if current is None:
            continue
        if _FRAME.match(line):
            current.frames.append(line.strip())
        elif artifact := _ARTIFACT.search(line):
            current.crash_file = Path(artifact.group(1)).name
        elif not current.frames and line.strip():
            current.message += line.strip() + "\n"
    return reports


def first_target_frame(frames: list[str]) -> str | None:
    """`file:line:col` (relative to the target) of the innermost frame inside the target code."""
    for frame in frames:
        m = re.search(re.escape(TARGET) + r"/(?!node_modules/)([^)\s]+:\d+:\d+)", frame)
        if m:
            return m.group(1)
    return None


def innermost(functions: list[ChangedFunction], line: int) -> ChangedFunction | None:
    """The smallest function containing `line` (named ones preferred), or None."""
    containing = [f for f in functions if f.start_line <= line <= f.end_line]
    named = [f for f in containing if f.name not in ("<anonymous>", "")] or containing
    return min(named, key=lambda f: f.end_line - f.start_line, default=None)
