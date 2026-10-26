"""JavaScript/TypeScript adapter (Jazzer.js). TypeScript compiles to JS, so one adapter serves both."""

import json
import re
from pathlib import Path

import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Node, Parser

from proofhound.core.adapters.base import FuzzerReport, LanguageAdapter
from proofhound.core.fuzzing.sandbox import OUT, TARGET
from proofhound.core.models import ChangedFunction

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
        tree = parser.parse(source)  # keep a reference: nodes are invalid once the tree is freed
        # Walk with a cursor and keep only plain values: holding many Node objects (e.g. a
        # node.children stack) crashes tree-sitter 0.26 during garbage collection on large files.
        spans: list[tuple[str, int, int]] = []
        cursor = tree.walk()
        while True:
            node = cursor.node
            if node.type in FUNCTION_NODES:
                spans.append((function_name(node), node.start_point.row + 1, node.end_point.row + 1))
            if cursor.goto_first_child():
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    return [
                        ChangedFunction(file=file, name=name, start_line=start, end_line=end,
                                        language=self.name)
                        for name, start, end in spans
                    ]

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
    # --timeout (Jazzer, milliseconds) reports a single input slower than it as a timeout. Without a
    # short per-input timeout, catastrophic regex backtracking (ReDoS) is invisible — the run just
    # stalls to -max_total_time and records no crash. Jazzer's own default is 5s; we set it
    # explicitly so the ReDoS signal does not silently depend on that default.
    def fuzz_command(self, time_s: int) -> list[str]:
        return [
            "jazzer", HARNESS, f"{OUT}/corpus", f"--timeout={PER_INPUT_TIMEOUT_MS}",
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
# A single fuzz input slower than this (Jazzer --timeout, milliseconds) is reported as a timeout —
# our ReDoS crash signal. Catastrophic backtracking blows well past it; a legit slow input will not.
PER_INPUT_TIMEOUT_MS = 10000
REDOS_KIND = "ReDoS"
_HEADER = re.compile(r"^==\d+== (.+)$")
_TIMEOUT = re.compile(r"ERROR: libFuzzer: timeout")
_FRAME = re.compile(r"^\s+at ")
_ARTIFACT = re.compile(r"Test unit written to (\S+)")


def parse_jazzer_output(output: str) -> list[FuzzerReport]:
    reports: list[FuzzerReport] = []
    current: FuzzerReport | None = None
    last_artifact: str | None = None
    for line in output.splitlines():
        if artifact := _ARTIFACT.search(line):
            # libFuzzer writes the offending input before its report (timeout) or after it (crash).
            last_artifact = Path(artifact.group(1)).name
            if current is not None and current.crash_file is None:
                current.crash_file = last_artifact
            continue
        # A per-input libFuzzer timeout = catastrophic backtracking = ReDoS. Its "==N== ERROR:
        # libFuzzer: timeout" line also matches the header pattern, so test for the timeout first.
        if _TIMEOUT.search(line):
            current = FuzzerReport(REDOS_KIND, True, "", [], last_artifact)
            reports.append(current)
            continue
        header = _HEADER.match(line)
        if header:
            title = header.group(1).strip()
            kind = "Uncaught Exception" if title.startswith("Uncaught Exception") else title
            current = FuzzerReport(kind, kind in SECURITY_DETECTORS, "", [], None)
            reports.append(current)
            continue
        if current is None:
            continue
        if _FRAME.match(line):
            current.frames.append(line.strip())
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
