"""Runs the agents in order for one commit and collects their results.

Analyzer -> Scheduler -> Harness -> Fuzzer -> Triage -> Patcher
"""

from dataclasses import dataclass, field

from proofhound.config import Settings
from proofhound.models import Crash, Finding, Harness, Patch, TriageResult
from proofhound.orchestrator.budget import Budget


@dataclass
class RunState:
    findings: list[Finding] = field(default_factory=list)
    harnesses: list[Harness] = field(default_factory=list)
    crashes: list[Crash] = field(default_factory=list)
    triaged: list[TriageResult] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)


class Pipeline:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.budget = Budget(
            timeout_s=settings.budgets.run_timeout_s,
            max_tokens=settings.budgets.max_tokens_per_run,
        )

    def run(self, repo: str, commit: str) -> RunState:
        raise NotImplementedError
