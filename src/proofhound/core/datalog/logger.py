"""Logs every harness attempt (prompt, output, check results) as JSON lines for training.

Records from benchmark cases whose split is "eval" are tagged so they can be excluded from
training data (no leakage between evaluation and training).
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class AttemptRecord:
    case: str  # benchmark case id or "<repo>@<commit>"
    split: str  # "eval" | "train" | "none"
    finding_id: str
    vuln_class: str | None
    attempt: int
    model: str
    prompt_version: str
    prompt: str
    output: str
    syntax_ok: bool = False
    loaded: bool = False
    reached: bool = False
    coverage_gain: bool = False
    crash_confirmed: bool = False
    failed_stage: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class AttemptLogger:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: AttemptRecord) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    def read(self) -> list[AttemptRecord]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [AttemptRecord(**json.loads(line)) for line in f if line.strip()]

    def mark_crash_confirmed(self, finding_id: str) -> None:
        """Set crash_confirmed on the last attempt for `finding_id` once fuzzing confirms it."""
        records = self.read()
        for record in reversed(records):
            if record.finding_id == finding_id:
                record.crash_confirmed = True
                break
        with self.path.open("w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
