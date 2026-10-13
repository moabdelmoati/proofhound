"""Data passed between agents. Every agent reads and writes these types only."""

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


ModelTier = Literal["small", "large", "none"]


class ChangedFunction(BaseModel):
    file: Path
    name: str
    start_line: int
    end_line: int
    language: str


class Finding(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    message: str
    file: Path
    line: int
    source: str | None = None
    sink: str | None = None
    vuln_class: str | None = None  # e.g. "command-injection"
    function: ChangedFunction | None = None


class Harness(BaseModel):
    finding_id: str
    code: str
    attempts: int = 1
    compiled: bool = False
    reached_target: bool = False
    produced_by: ModelTier = "large"


class Crash(BaseModel):
    finding_id: str
    kind: str  # bug-detector title, e.g. "Command Injection"
    input_path: Path
    stack_trace: str
    signature: str  # kind + first frame in the target; used for deduplication
    sink_location: str | None = None  # "file:line:col" of the first frame in the target
    reproduced: int = 0  # successful re-runs of the crash input


class TriageResult(BaseModel):
    crash: Crash
    confidence: float = Field(ge=0.0, le=1.0)
    cvss: float | None = None
    pov_path: Path | None = None
    produced_by: ModelTier = "large"


class Patch(BaseModel):
    finding_id: str
    diff: str
    regression_test: str
    validated: bool = False
    produced_by: ModelTier = "large"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"  # reproducible security bug-detector report
    NOT_CONFIRMED = "not_confirmed"  # harness worked, fuzzing found nothing in the budget
    HARNESS_FAILED = "harness_failed"  # no working harness after all repair attempts
    SKIPPED_BUDGET = "skipped_budget"  # run budget exhausted before this finding
    ERROR = "error"  # infrastructure failure (sandbox, LLM API, ...)


class FindingResult(BaseModel):
    finding: Finding
    status: FindingStatus
    harness: Harness | None = None
    crashes: list[Crash] = []
    tokens_used: int = 0
    duration_s: float = 0.0
    detail: str = ""  # error message or the reason for the status


class RunReport(BaseModel):
    tool_version: str
    repo: str
    commit: str
    started_at: str  # ISO 8601
    duration_s: float = 0.0
    tokens_used: int = 0
    models: dict[str, str] = {}  # agent -> model id
    changed_functions: int = 0
    sast_findings_total: int = 0  # before filtering to changed functions
    results: list[FindingResult] = []

    def count(self, status: FindingStatus) -> int:
        return sum(1 for r in self.results if r.status == status)
