"""Fuzz Claude-authored harnesses through the same pipeline the other models used.

Claude (the Claude Code session) writes one harness per ground-truth finding into
  .trash_cleanup/claude_harnesses/<case>__<finding_id>.js
using only the pipeline prompt (single-shot, same as the API models received).

This script runs each through check_harness + the fuzzer, exactly as compare.py does, and
writes runs/gt-claude/summary.json so the result is directly comparable.
"""
import json
import sys
from pathlib import Path

import yaml

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.core.analysis.semgrep import SemgrepEngine
from proofhound.core.config import load_settings
from proofhound.core.datalog.logger import AttemptLogger
from proofhound.core.fuzzing.fuzzer import FuzzerAgent, FuzzJob
from proofhound.core.fuzzing.sandbox import DockerSandbox
from proofhound.core.harness.check import check_harness

sys.path.insert(0, "src")
from proofhound.evaluation.compare import ground_truth_findings  # noqa: E402

HARNESS_DIR = Path(".trash_cleanup/claude_harnesses")
OUT = Path("runs/gt-claude")
BENCH = Path("benchmark/cases")


def main() -> None:
    settings = load_settings(Path("configs/default.yaml"))
    settings.harness.class_seeds = True
    adapter = JavaScriptAdapter()
    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), Path("rules/semgrep/javascript"))
    sandbox = DockerSandbox(settings.sandbox)
    sandbox.check_ready()
    OUT.mkdir(parents=True, exist_ok=True)
    logger = AttemptLogger(OUT / "attempts_claude.jsonl")
    fuzzer = FuzzerAgent(sandbox, adapter, attempt_logger=logger, class_seeds=True)

    rows = []
    for case_dir in sorted(d for d in BENCH.iterdir() if (d / "case.yaml").exists() and (d / "repo").exists()):
        manifest = yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))
        case_id, repo = manifest["id"], case_dir / "repo"
        try:
            analysis = analyzer.run(AnalyzeJob(repo, manifest["commit"]))
        except Exception as e:
            print(f"[{case_id}] analyzer error: {e}")
            continue
        gts = ground_truth_findings(analysis.findings, manifest, case_id)
        if not gts:
            continue
        finding = gts[0]
        hpath = HARNESS_DIR / f"{case_id}__{finding.id}.js"
        if not hpath.is_file():
            print(f"[{case_id}] no Claude harness written yet ({hpath.name}) — skipping")
            continue
        code = hpath.read_text(encoding="utf-8")
        out = OUT / case_id / finding.id
        out.mkdir(parents=True, exist_ok=True)
        (out / "harness.js").write_text(code, encoding="utf-8")

        check = check_harness(sandbox, adapter, finding.function, repo, out, settings.harness.probe_time_s)
        confirmed = False
        if check.reached:
            confirmed = fuzzer.run(FuzzJob(finding, repo, out, settings.budgets.fuzz_time_per_target_s)).confirmed
        stage = "confirmed" if confirmed else ("reached" if check.reached else
                ("loaded" if check.loaded else ("syntax_ok" if check.syntax_ok else "failed")))
        rows.append({"case": case_id, "finding_id": finding.id, "vuln_class": finding.vuln_class,
                     "syntax_ok": check.syntax_ok, "loaded": check.loaded, "reached": check.reached,
                     "confirmed": confirmed, "stage": stage})
        print(f"[{case_id}] {finding.vuln_class}: {stage}")

    n = len(rows)
    conf = sum(r["confirmed"] for r in rows)
    reach = sum(r["reached"] for r in rows)
    load = sum(r["loaded"] for r in rows)
    summary = {"models": [{"model": "claude", "findings": n, "errors": 0,
               "syntax_ok": f"{sum(r['syntax_ok'] for r in rows)} ({100*sum(r['syntax_ok'] for r in rows)//max(n,1)}%)",
               "loaded": f"{load} ({100*load//max(n,1)}%)", "reached": f"{reach} ({100*reach//max(n,1)}%)",
               "confirmed": f"{conf} ({100*conf//max(n,1)}%)"}], "per_finding": rows}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nClaude: {conf}/{n} confirmed, {reach}/{n} reached, {load}/{n} loaded")


if __name__ == "__main__":
    main()
