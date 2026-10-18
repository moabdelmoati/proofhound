"""Python adapter: changed-function extraction and Atheris harness scaffolding.

Term 1 wires Python only for the analysis side (diff -> changed functions -> Semgrep), which
proves the adapter layer generalizes without touching the agents. The fuzzing hooks
(fuzz/replay/coverage/report parsing) target Atheris and are completed in Term 2, so this
adapter raises NotImplementedError for them rather than pretending to fuzz.
"""

from pathlib import Path

import tree_sitter_python as ts_python
from tree_sitter import Language, Node, Parser

from proofhound.core.adapters.base import FuzzerReport, LanguageAdapter
from proofhound.core.models import ChangedFunction

_LANGUAGE = Language(ts_python.language())
FUNCTION_NODES = {"function_definition", "lambda"}

HARNESS_TEMPLATE = '''\
import atheris
import sys

with atheris.instrument_imports():
    import {module}


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # Build arguments from `fdp` and call the target function.


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
'''


def _qualified_name(node: Node) -> str:
    """`Class.method`, `outer.inner`, the function's own name, or `<lambda>`."""
    name_node = node.child_by_field_name("name")
    own = name_node.text.decode("utf-8", "replace") if name_node is not None and name_node.text else ""
    if node.type == "lambda":
        return "<lambda>"
    # Walk up through enclosing classes/functions for a dotted path.
    prefix = []
    parent = node.parent
    while parent is not None:
        if parent.type in ("class_definition", "function_definition"):
            pn = parent.child_by_field_name("name")
            if pn is not None and pn.text:
                prefix.append(pn.text.decode("utf-8", "replace"))
        parent = parent.parent
    return ".".join([*reversed(prefix), own]) if prefix else own


class PythonAdapter(LanguageAdapter):
    name = "python"
    extensions = (".py",)
    fuzzer = "atheris"
    sandbox_image = "proofhound/atheris:latest"  # built in Term 2

    def functions(self, file: Path, source: bytes) -> list[ChangedFunction]:
        parser = Parser(_LANGUAGE)
        tree = parser.parse(source)
        spans: list[tuple[str, int, int]] = []
        cursor = tree.walk()
        while True:
            node = cursor.node
            if node.type in FUNCTION_NODES:
                spans.append((_qualified_name(node), node.start_point.row + 1, node.end_point.row + 1))
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

    def harness_template(self, module: str = "TARGET_MODULE") -> str:
        return HARNESS_TEMPLATE.replace("{module}", module)

    def fuzz_command(self, time_s: int) -> list[str]:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")

    def replay_command(self, inputs: str) -> list[str]:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")

    def coverage_command(self, inputs: str) -> list[str]:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")

    def function_hits(self, out: Path, fn: ChangedFunction) -> int | None:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")

    def parse_reports(self, output: str) -> list[FuzzerReport]:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")

    def target_frame(self, frames: list[str]) -> str | None:
        raise NotImplementedError("Atheris fuzzing is implemented in Term 2.")
