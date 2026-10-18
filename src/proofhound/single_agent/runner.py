"""Run the single agent on one commit; write the same report the multi-agent pipeline writes.

Outputs in `run_dir`: report.json (and report.sarif) in the shared RunReport format, so both
architectures are scored by the same code, plus single_agent.json (run summary, including the
protocol-error count) and transcript.jsonl (every step).
"""

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from proofhound import __version__
from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.analyzer import AnalyzerAgent
from proofhound.core.analysis.semgrep import SemgrepEngine
from proofhound.core.budget import Budget
from proofhound.core.config import Settings
from proofhound.core.fuzzing.fuzzer import FuzzerAgent
from proofhound.core.fuzzing.sandbox import DockerSandbox
from proofhound.core.llm.client import build_client
from proofhound.core.models import FindingResult, FindingStatus, RunReport
from proofhound.core.reporting.json_report import write_json_report
from proofhound.core.reporting.sarif import write_sarif_report
from proofhound.single_agent.agent import SingleAgent, SingleAgentResult, load_system_prompt
from proofhound.single_agent.tools import AgentTools, FindingOutcome

MODULE_PLACEHOLDER = "<module_path from run_sast>"


def scan_commit(
    settings: Settings, repo: Path, commit: str, run_dir: Path, model_key: str | None = None,
) -> tuple[RunReport, SingleAgentResult]:
    key = model_key or settings.single_agent.model
    model_cfg = settings.models[key]  # KeyError: the caller reports the unknown model
    run_dir.mkdir(parents=True, exist_ok=True)
    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    tools = AgentTools(
        repo=repo, commit=commit, adapter=adapter,
        analyzer=AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir),
        sandbox=sandbox, fuzzer=FuzzerAgent(sandbox, adapter), out=run_dir,
        probe_time_s=settings.harness.probe_time_s,
        fuzz_time_s=settings.budgets.fuzz_time_per_target_s,
    )
    version, system_prompt = load_system_prompt(adapter.harness_template(module=MODULE_PLACEHOLDER))
    agent = SingleAgent(
        client=build_client(key, model_cfg), tools=tools, system_prompt=system_prompt,
        budget=Budget(settings.budgets.run_timeout_s, settings.budgets.max_tokens_per_run),
        task=f"Prove a vulnerability introduced by commit {commit} in the repository.",
        max_steps=settings.single_agent.max_steps,
    )

    started_at = datetime.now(UTC).isoformat()
    start = time.monotonic()
    result = agent.run()
    report = RunReport(
        tool_version=__version__, repo=str(repo), commit=commit, started_at=started_at,
        duration_s=time.monotonic() - start, tokens_used=result.tokens_used,
        models={"single_agent": model_cfg.model or key},
        changed_functions=tools.changed_functions, sast_findings_total=tools.sast_findings_total,
        results=[_finding_result(o, result.stop_reason) for o in result.outcomes],
    )
    write_json_report(report, run_dir)
    if "sarif" in settings.output.formats:
        write_sarif_report(report, run_dir)
    _write_run_files(run_dir, version, key, result)
    return report, result


def _finding_result(o: FindingOutcome, stop_reason: str) -> FindingResult:
    if o.proven:
        status, detail = FindingStatus.CONFIRMED, ""
    elif o.reached:
        status, detail = FindingStatus.NOT_CONFIRMED, "harness reached the target; no crash confirmed"
    elif o.harness_written:
        status, detail = FindingStatus.HARNESS_FAILED, "no harness reached the target"
    elif stop_reason in {"budget", "max_steps"}:
        status, detail = FindingStatus.SKIPPED_BUDGET, f"not attempted before the run stopped ({stop_reason})"
    else:
        status, detail = FindingStatus.HARNESS_FAILED, "the agent did not attempt this finding"
    return FindingResult(finding=o.finding, status=status, crashes=o.crashes, detail=detail)


def _write_run_files(run_dir: Path, version: str, model_key: str, result: SingleAgentResult) -> None:
    summary = {
        "prompt_version": version, "model": model_key, "stop_reason": result.stop_reason,
        "steps": len(result.steps), "protocol_errors": result.protocol_errors,
        "tokens_used": result.tokens_used,
        "findings": len(result.outcomes), "proven": len(result.proven),
    }
    (run_dir / "single_agent.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (run_dir / "transcript.jsonl").open("w", encoding="utf-8") as f:
        for s in result.steps:
            f.write(json.dumps({
                "step": s.number, "tool": s.tool, "args": s.args, "thought": s.thought,
                "observation": s.observation, "protocol_error": s.protocol_error,
                "tokens": s.tokens, "reply": s.reply if s.protocol_error else None,
            }, ensure_ascii=False) + "\n")
