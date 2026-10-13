"""Runs the fuzzer in the sandbox, collects bug-detector reports, and replays each crash input.

Only security bug-detector reports that reproduce on every replay become confirmed `Crash`es.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from proofhound.adapters.base import FuzzerReport, LanguageAdapter
from proofhound.agents.base import Agent
from proofhound.models import Crash, Finding
from proofhound.sandbox.docker_runner import DockerSandbox, SandboxResult


@dataclass
class FuzzJob:
    finding: Finding
    target: Path  # code under test (host path)
    out: Path  # holds harness.js; receives corpus/ and crash files
    time_s: int


@dataclass
class FuzzOutcome:
    crashes: list[Crash] = field(default_factory=list)
    other_reports: list[FuzzerReport] = field(default_factory=list)  # exceptions, timeouts
    run: SandboxResult | None = None


class FuzzerAgent(Agent[FuzzJob, FuzzOutcome]):
    name = "fuzzer"

    def __init__(self, sandbox: DockerSandbox, adapter: LanguageAdapter, replays: int = 3):
        self.sandbox = sandbox
        self.adapter = adapter
        self.replays = replays

    def run(self, data: FuzzJob) -> FuzzOutcome:
        (data.out / "corpus").mkdir(parents=True, exist_ok=True)
        result = self.sandbox.run(
            self.adapter.fuzz_command(data.time_s), data.target, data.out,
            timeout_s=data.time_s + 60,
        )
        (data.out / "fuzz.log").write_text(result.output, encoding="utf-8")
        outcome = FuzzOutcome(run=result)
        for report in self.adapter.parse_reports(result.output):
            if not report.is_vulnerability or report.crash_file is None:
                outcome.other_reports.append(report)
                continue
            crash = self._to_crash(data, report)
            crash.reproduced = self._replay(data, report)
            if crash.reproduced == self.replays:
                outcome.crashes.append(crash)
            else:
                outcome.other_reports.append(report)
        return outcome

    def _to_crash(self, data: FuzzJob, report: FuzzerReport) -> Crash:
        sink = self.adapter.target_frame(report.frames)
        trace = report.message + "\n".join(report.frames)
        signature = hashlib.sha1(f"{report.kind}|{sink}".encode()).hexdigest()[:12]
        return Crash(
            finding_id=data.finding.id,
            kind=report.kind,
            input_path=data.out / report.crash_file,
            stack_trace=trace,
            signature=signature,
            sink_location=sink,
        )

    def _replay(self, data: FuzzJob, report: FuzzerReport) -> int:
        reproduced = 0
        for _ in range(self.replays):
            result = self.sandbox.run(
                self.adapter.replay_command(report.crash_file), data.target, data.out,
                timeout_s=60,
            )
            if any(r.kind == report.kind for r in self.adapter.parse_reports(result.output)):
                reproduced += 1
        return reproduced
