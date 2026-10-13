"""One adapter per language. Adding a language must not require changes to the agents."""

from abc import ABC, abstractmethod
from pathlib import Path

from proofhound.models import ChangedFunction


class LanguageAdapter(ABC):
    name: str
    extensions: tuple[str, ...]
    fuzzer: str
    sandbox_image: str

    @abstractmethod
    def extract_functions(self, file: Path, changed_lines: set[int]) -> list[ChangedFunction]: ...

    @abstractmethod
    def harness_template(self) -> str: ...

    @abstractmethod
    def fuzz_command(self, harness_path: Path, time_s: int) -> list[str]: ...
