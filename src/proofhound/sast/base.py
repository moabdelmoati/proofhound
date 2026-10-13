"""SAST engine interface so Semgrep can be swapped for our own engine."""

from abc import ABC, abstractmethod
from pathlib import Path

from proofhound.models import Finding


class SastEngine(ABC):
    @abstractmethod
    def scan(self, files: list[Path], rules_dir: Path) -> list[Finding]: ...
