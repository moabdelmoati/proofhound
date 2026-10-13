"""One adapter per language. Adding a language must not require changes to the agents."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from proofhound.models import ChangedFunction


class LanguageAdapter(ABC):
    name: str
    extensions: tuple[str, ...]
    fuzzer: str
    sandbox_image: str

    @abstractmethod
    def extract_functions(
        self, file: Path, changed_lines: set[int], root: Path = Path(".")
    ) -> list[ChangedFunction]: ...

    @abstractmethod
    def harness_template(self) -> str: ...

    @abstractmethod
    def fuzz_command(self, time_s: int) -> list[str]:
        """Fuzz `<out>/harness` and store crashes in `<out>`, corpus in `<out>/corpus`."""

    @abstractmethod
    def replay_command(self, inputs: str) -> list[str]:
        """Run the harness once on a file or directory under `<out>`, no fuzzing."""

    @abstractmethod
    def coverage_command(self, inputs: str) -> list[str]:
        """Like `replay_command`, also writing a coverage report to `<out>/coverage`."""

    @abstractmethod
    def function_hits(self, out: Path, fn: ChangedFunction) -> int | None:
        """Times `fn` ran according to the last coverage report; None if no report."""

    @abstractmethod
    def parse_reports(self, output: str) -> list["FuzzerReport"]:
        """Bug reports in the fuzzer's console output."""

    @abstractmethod
    def target_frame(self, frames: list[str]) -> str | None:
        """`file:line:col` (relative to the target) of the innermost stack frame in target code."""


@dataclass
class FuzzerReport:
    kind: str  # bug-detector title, or "Uncaught Exception" / "Timeout"
    is_vulnerability: bool  # True only for security bug detectors
    message: str
    frames: list[str]  # "at fn (file:line:col)" lines, innermost first
    crash_file: str | None  # name under <out>, if the fuzzer saved the input


def innermost(functions: list[ChangedFunction], line: int) -> ChangedFunction | None:
    """The smallest function containing `line` (named ones preferred), or None."""
    containing = [f for f in functions if f.start_line <= line <= f.end_line]
    named = [f for f in containing if f.name not in ("<anonymous>", "")] or containing
    return min(named, key=lambda f: f.end_line - f.start_line, default=None)
