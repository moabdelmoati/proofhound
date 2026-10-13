"""SAST engine interface so Semgrep can be swapped for our own engine."""

from abc import ABC, abstractmethod
from pathlib import Path

from proofhound.models import Finding


class SastEngine(ABC):
    @abstractmethod
    def scan(self, files: list[Path], rules_dir: Path, root: Path = Path(".")) -> list[Finding]:
        """Scan `files` (relative to `root`) and return findings with paths relative to `root`."""
