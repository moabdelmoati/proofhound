"""Runs the Analyzer over benchmark cases and scores it against the ground-truth sink.

A case counts as detected by SAST when a finding in a changed function lies on the
ground-truth sink line (within `LINE_TOLERANCE`, since Semgrep reports the start of the
tainted argument, which can sit on a different line than the call in a multi-line expression).
Every other finding in the case counts as a SAST-only false positive.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

from proofhound.agents.analyzer import AnalyzeJob, AnalyzerAgent

LINE_TOLERANCE = 2


@dataclass
class SastCaseResult:
    case: str
    vuln_class: str
    commit_mode: str
    sink: str
    changed_functions: int
    findings: int
    detected: bool
    false_positives: int
    error: str = ""


def load_manifest(case_dir: Path) -> dict:
    return yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))


def score_sast(analyzer: AnalyzerAgent, case_dir: Path) -> SastCaseResult:
    m = load_manifest(case_dir)
    sink_file, sink_line, _ = m["sink"].rsplit(":", 2)
    base = SastCaseResult(m["id"], m["vuln_class"], m["commit_mode"], m["sink"], 0, 0, False, 0)
    try:
        analysis = analyzer.run(AnalyzeJob(case_dir / "repo", m["commit"]))
    except Exception as e:  # noqa: BLE001 - report and continue with the next case
        base.error = f"{type(e).__name__}: {str(e)[:200]}"
        return base
    hits = [
        f for f in analysis.findings
        if f.file.as_posix() == sink_file and abs(f.line - int(sink_line)) <= LINE_TOLERANCE
    ]
    base.changed_functions = len(analysis.changed_functions)
    base.findings = len(analysis.findings)
    base.detected = bool(hits)
    base.false_positives = len(analysis.findings) - len(hits)
    return base


def run_sast_benchmark(analyzer: AnalyzerAgent, cases_root: Path, out: Path) -> list[SastCaseResult]:
    results = [
        score_sast(analyzer, d)
        for d in sorted(cases_root.iterdir())
        if (d / "case.yaml").exists() and (d / "repo").exists()
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    return results
