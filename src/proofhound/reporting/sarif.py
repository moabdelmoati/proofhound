"""Writes confirmed findings as SARIF 2.1.0 for CI code-scanning views.

SARIF is what GitHub's "Security" tab and GitLab's security dashboard read, so emitting it lets
ProofHound results show up inline on a pull/merge request. Only confirmed findings carry the
`security-severity` that makes code scanning surface them; unconfirmed findings are emitted at a
lower level so they stay visible without blocking.
"""

import json
from pathlib import Path

from proofhound.models import FindingStatus, RunReport, Severity

_SARIF_LEVEL = {
    FindingStatus.CONFIRMED: "error",
    FindingStatus.NOT_CONFIRMED: "note",
    FindingStatus.HARNESS_FAILED: "note",
    FindingStatus.SKIPPED_BUDGET: "note",
    FindingStatus.ERROR: "note",
}
# GitHub maps security-severity (0-10) to critical/high/medium/low buckets.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


def build_sarif(report: RunReport) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for r in report.results:
        f = r.finding
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
                    "tags": ["security", f.vuln_class or "vulnerability"],
                },
            }
        text = f"[{r.status.value}] {f.message}" if f.message else f"[{r.status.value}] {f.rule_id}"
        if r.crashes:
            c = r.crashes[0]
            text += f" | confirmed {c.kind} at {c.sink_location}, reproduced {c.reproduced}x"
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(r.status, "note"),
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.as_posix()},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
            "properties": {
                "status": r.status.value,
                "proofhound_confirmed": r.status == FindingStatus.CONFIRMED,
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "ProofHound",
                "informationUri": "https://github.com/moabdelmoati/proofhound",
                "version": report.tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif_report(report: RunReport, run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "report.sarif"
    path.write_text(json.dumps(build_sarif(report), indent=2), encoding="utf-8")
    return path
