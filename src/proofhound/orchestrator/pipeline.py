"""Runs the agents in order for one commit and writes runs/<commit>/.

Analyzer -> (per finding, by severity) harness step -> Fuzzer -> report

The harness step is any object with `produce(finding, target, out) -> Harness | None` that
leaves a working harness file in `out`. Its implementation is not part of this module.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from proofhound import __version__
from proofhound.adapters.base import LanguageAdapter
from proofhound.agents.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.agents.fuzzer import FuzzerAgent, FuzzJob
from proofhound.config import Settings
from proofhound.models import Finding, FindingResult, FindingStatus, Harness, RunReport
from proofhound.orchestrator.budget import Budget
from proofhound.reporting.json_report import write_json_report


class HarnessStep(Protocol):
    tokens_used: int

    def produce(self, finding: Finding, target: Path, out: Path) -> Harness | None: ...


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        analyzer: AnalyzerAgent,
        harness_step: HarnessStep,
        fuzzer: FuzzerAgent,
        adapter: LanguageAdapter,
    ):
        self.settings = settings
        self.analyzer = analyzer
        self.harness_step = harness_step
        self.fuzzer = fuzzer
        self.adapter = adapter

    def run(self, repo: Path, commit: str, run_dir: Path) -> RunReport:
        budget = Budget(
            timeout_s=self.settings.budgets.run_timeout_s,
            max_tokens=self.settings.budgets.max_tokens_per_run,
        )
        start = time.monotonic()
        report = RunReport(
            tool_version=__version__,
            repo=str(repo),
            commit=commit,
            started_at=datetime.now(timezone.utc).isoformat(),
            models={"harness": self.settings.harness.model},
        )

        analysis = self.analyzer.run(AnalyzeJob(repo, commit))
        report.changed_functions = len(analysis.changed_functions)
        report.sast_findings_total = analysis.all_sast_findings

        for finding in analysis.findings:
            if budget.exhausted:
                report.results.append(
                    FindingResult(finding=finding, status=FindingStatus.SKIPPED_BUDGET)
                )
                continue
            result = self._process(finding, repo, run_dir / finding.id)
            budget.charge(result.tokens_used)
            report.results.append(result)

        report.duration_s = time.monotonic() - start
        report.tokens_used = budget.tokens_used
        write_json_report(report, run_dir)
        return report

    def _process(self, finding: Finding, repo: Path, out: Path) -> FindingResult:
        start = time.monotonic()
        out.mkdir(parents=True, exist_ok=True)
        (out / "finding.json").write_text(finding.model_dump_json(indent=2), encoding="utf-8")
        tokens_before = self.harness_step.tokens_used
        try:
            harness = self.harness_step.produce(finding, repo, out)
        except Exception as e:  # noqa: BLE001 - one failing finding must not stop the run
            tokens = self.harness_step.tokens_used - tokens_before
            return FindingResult(
                finding=finding, status=FindingStatus.ERROR, detail=f"harness step: {e}",
                tokens_used=tokens, duration_s=time.monotonic() - start,
            )
        tokens = self.harness_step.tokens_used - tokens_before
        if harness is None:
            return FindingResult(
                finding=finding, status=FindingStatus.HARNESS_FAILED, tokens_used=tokens,
                duration_s=time.monotonic() - start,
            )
        try:
            outcome = self.fuzzer.run(
                FuzzJob(finding, repo, out, self.settings.budgets.fuzz_time_per_target_s)
            )
        except Exception as e:  # noqa: BLE001
            return FindingResult(
                finding=finding, status=FindingStatus.ERROR, harness=harness,
                tokens_used=tokens, detail=f"fuzzer: {e}", duration_s=time.monotonic() - start,
            )
        status = FindingStatus.CONFIRMED if outcome.crashes else FindingStatus.NOT_CONFIRMED
        return FindingResult(
            finding=finding, status=status, harness=harness, crashes=outcome.crashes,
            tokens_used=tokens, duration_s=time.monotonic() - start,
        )
