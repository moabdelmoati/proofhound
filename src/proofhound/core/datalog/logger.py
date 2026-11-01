"""Logs every harness attempt (prompt, output, check results) as JSON lines for training.

Records from benchmark cases whose split is "eval" are tagged so they can be excluded from
training data (no leakage between evaluation and training).
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml


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
    failed_stage: str | None = None  # syntax | probe | reach | sandbox | empty | no_harness
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0  # part of output_tokens
    stop_reason: str | None = None  # "length" = the reply hit the output token limit
    temperature: float | None = None
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

    def mark_crash_confirmed(self, finding_id: str, case: str | None = None) -> None:
        """Set crash_confirmed on the last attempt for `finding_id` (in `case`, when given) once
        fuzzing confirms it. Finding ids hash rule, path and position, so two cases can share one."""
        records = self.read()
        for record in reversed(records):
            if record.finding_id == finding_id and (case is None or record.case == case):
                record.crash_confirmed = True
                break
        with self.path.open("w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")


def _manifest(target: Path) -> dict:
    manifest = target.parent / "case.yaml"
    if manifest.is_file():
        try:
            return yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            pass
    return {}


def case_id(target: Path) -> str:
    """The benchmark case id of a checked-out target (`<case>/repo`), or "<repo>@unknown"."""
    data = _manifest(target)
    if data:
        return str(data.get("id") or target.parent.name)
    return f"{target.name}@unknown"


def case_split(target: Path) -> str:
    split = _manifest(target).get("split")
    return split if split in {"train", "eval"} else "none"
