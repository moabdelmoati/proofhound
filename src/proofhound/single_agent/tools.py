"""The tools the single agent drives. None of them calls an LLM.

They wrap the same infrastructure the multi-agent pipeline uses — the Analyzer, the shared harness
check, the Fuzzer — so the two architectures are compared on identical capabilities. Every tool
takes JSON arguments and returns a JSON-serializable dict; failures come back as {"error": ...}
for the model to read, never as exceptions.

Outcomes are recorded from what the tools observed, not from what the model claims: a finding is
proven only when `check_harness` saw the target reached and `run_fuzzer` confirmed a crash.
"""

from dataclasses import dataclass, field
from pathlib import Path

from proofhound.core.adapters.base import LanguageAdapter
from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.core.analysis.diff import changed_lines
from proofhound.core.fuzzing.fuzzer import FuzzerAgent, FuzzJob
from proofhound.core.fuzzing.sandbox import TARGET, DockerSandbox
from proofhound.core.harness.agent import extract_harness_code
from proofhound.core.harness.check import check_harness
from proofhound.core.models import Crash, Finding

MAX_ERROR_CHARS = 3000


@dataclass
class FindingOutcome:
    finding: Finding
    harness_written: bool = False
    checks: int = 0
    reached: bool = False  # some harness reached the target (kept once true)
    ready: bool = False  # the harness saved now passed check_harness; gates run_fuzzer
    fuzz_runs: int = 0
    crashes: list[Crash] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return bool(self.crashes)

    @property
    def proven(self) -> bool:
        return self.reached and self.confirmed


@dataclass
class AgentTools:
    repo: Path
    commit: str
    adapter: LanguageAdapter
    analyzer: AnalyzerAgent
    sandbox: DockerSandbox
    fuzzer: FuzzerAgent
    out: Path
    probe_time_s: int = 5
    fuzz_time_s: int = 30
    max_file_chars: int = 20_000
    outcomes: dict[str, FindingOutcome] = field(default_factory=dict)
    sast_findings_total: int = 0
    changed_functions: int = 0

    def git_diff(self) -> dict:
        """Changed files and their added line numbers in the commit."""
        changed = changed_lines(self.repo, self.commit, self.adapter.extensions)
        return {"changed": {f.as_posix(): sorted(lines) for f, lines in changed.items()}}

    def read_file(self, path: str, start: int = 1, end: int | None = None) -> dict:
        """A file in the repository (optionally a line range), capped at `max_file_chars`."""
        target = (self.repo / path).resolve()
        if not target.is_relative_to(self.repo.resolve()):
            return {"error": "path escapes the repository"}
        if not target.is_file():
            return {"error": f"not a file: {path}"}
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        end = min(end or len(lines), len(lines))
        content = "\n".join(lines[max(start, 1) - 1:end])
        return {"path": path, "start": start, "end": end, "total_lines": len(lines),
                "content": content[: self.max_file_chars]}

    def run_sast(self) -> dict:
        """SAST findings inside functions the commit changed, most severe first."""
        analysis = self.analyzer.run(AnalyzeJob(self.repo, self.commit))
        self.sast_findings_total = analysis.all_sast_findings
        self.changed_functions = len(analysis.changed_functions)
        for f in analysis.findings:
            self.outcomes.setdefault(f.id, FindingOutcome(f))
        return {"findings": [_summary(f) for f in analysis.findings]}

    def write_harness(self, finding_id: str, code: str) -> dict:
        """Save the harness for a finding (replacing any earlier one)."""
        outcome = self.outcomes.get(finding_id)
        if outcome is None:
            return {"error": f"unknown finding_id {finding_id!r}; call run_sast first"}
        workdir = self._workdir(finding_id)
        (workdir / "harness.js").write_text(extract_harness_code(code), encoding="utf-8")
        outcome.harness_written = True
        outcome.ready = False  # a new harness must pass the check again
        return {"saved": True, "finding_id": finding_id}

    def check_harness(self, finding_id: str) -> dict:
        """Syntax check, a short fuzz probe, and coverage of the target function."""
        outcome = self.outcomes.get(finding_id)
        if outcome is None:
            return {"error": f"unknown finding_id {finding_id!r}; call run_sast first"}
        if not outcome.harness_written:
            return {"error": "no harness saved for this finding; call write_harness first"}
        check = check_harness(
            self.sandbox, self.adapter, outcome.finding.function, self.repo,
            self._workdir(finding_id), self.probe_time_s,
        )
        if check.sandbox_error is not None:
            return {"error": f"sandbox failure: {check.error[:MAX_ERROR_CHARS]}"}
        outcome.checks += 1
        outcome.ready = check.reached
        outcome.reached = outcome.reached or check.reached
        return {
            "syntax_ok": check.syntax_ok, "loaded": check.loaded, "reached": check.reached,
            "failed_stage": check.failed_stage, "error": check.error[:MAX_ERROR_CHARS],
        }

    def run_fuzzer(self, finding_id: str) -> dict:
        """Fuzz a harness that reached its target; report confirmed (reproduced) crashes."""
        outcome = self.outcomes.get(finding_id)
        if outcome is None:
            return {"error": f"unknown finding_id {finding_id!r}; call run_sast first"}
        if not outcome.ready:
            return {"error": "the saved harness has not reached the target function; "
                             "fix it and pass check_harness first"}
        result = self.fuzzer.run(
            FuzzJob(outcome.finding, self.repo, self._workdir(finding_id), self.fuzz_time_s)
        )
        outcome.fuzz_runs += 1
        outcome.crashes = result.crashes or outcome.crashes  # a later empty run keeps a proof
        return {
            "confirmed": bool(result.crashes),
            "crashes": [
                {"kind": c.kind, "sink_location": c.sink_location, "reproduced": c.reproduced}
                for c in result.crashes
            ],
            "other_reports": [r.kind for r in result.other_reports],
        }

    def _workdir(self, finding_id: str) -> Path:
        workdir = self.out / finding_id
        workdir.mkdir(parents=True, exist_ok=True)
        return workdir


def _summary(f: Finding) -> dict:
    fn = f.function
    return {
        "finding_id": f.id, "rule": f.rule_id, "severity": f.severity.value,
        "vuln_class": f.vuln_class, "file": f.file.as_posix(), "line": f.line,
        "function": {"name": fn.name, "start_line": fn.start_line, "end_line": fn.end_line}
        if fn else None,
        "source": f.source, "sink": f.sink, "message": f.message,
        "module_path": f"{TARGET}/{f.file.as_posix()}",
    }


# Provider-agnostic tool descriptions. The agent loop renders them into the system prompt and
# maps a call by `name` to the AgentTools method of the same name.
TOOL_SPECS = [
    {"name": "git_diff", "description": "List the files the commit changed and their added lines.",
     "args": {}},
    {"name": "read_file", "description": "Read a repository file, optionally a line range.",
     "args": {"path": "string (repository-relative)", "start": "integer, optional",
              "end": "integer, optional"}},
    {"name": "run_sast", "description": "SAST findings inside changed functions, most severe first. "
     "Each has a finding_id and the module_path to require in a harness.", "args": {}},
    {"name": "write_harness", "description": "Save the Jazzer.js harness for a finding. Put the code "
     "in a ```javascript block after the JSON instead of in args if you prefer.",
     "args": {"finding_id": "string", "code": "string (the complete harness)"}},
    {"name": "check_harness", "description": "Run the saved harness: syntax, a short fuzz probe, and "
     "whether coverage reached the target function. Returns the failing stage and its error.",
     "args": {"finding_id": "string"}},
    {"name": "run_fuzzer", "description": "Fuzz a harness that passed check_harness; reports crashes "
     "a security bug detector confirmed and reproduced.", "args": {"finding_id": "string"}},
    {"name": "finish", "description": "End the run.", "args": {"summary": "string"}},
]
