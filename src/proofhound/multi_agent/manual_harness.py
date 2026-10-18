"""Harness step that uses hand-written harnesses: <dir>/<function name>.js.

Used to test the pipeline end to end without an LLM, and for the defense demo fallback.
"""

import shutil
from pathlib import Path

from proofhound.core.models import Finding, Harness


class ManualHarnessStep:
    tokens_used = 0

    def __init__(self, harness_dir: Path):
        self.harness_dir = harness_dir

    def produce(self, finding: Finding, target: Path, out: Path) -> Harness | None:
        name = finding.function.name if finding.function else ""
        source = self.harness_dir / f"{name}.js"
        if not name or not source.exists():
            return None
        shutil.copy(source, out / "harness.js")
        return Harness(
            finding_id=finding.id, code=source.read_text(encoding="utf-8"),
            compiled=True, reached_target=True, produced_by="none",
        )
