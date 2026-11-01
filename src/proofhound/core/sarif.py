"""Render a RunReport as SARIF 2.1.0 for GitHub code scanning.

Confirmed findings (a reproduced crash) become `error`-level results; SAST findings that
fuzzing could not confirm within the budget become `note`-level. Infrastructure failures
(ERROR) and findings skipped for budget are omitted — they are not security signal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from proofhound.core.models import Finding, FindingStatus, RunReport, Severity

INFORMATION_URI = "https://github.com/moabdelmoati/proofhound"

# For SAST-only results (analyze): nothing is proven, so map severity to a non-error level.
_SEVERITY_LEVEL = {
    Severity.CRITICAL: "warning",
    Severity.HIGH: "warning",
    Severity.MEDIUM: "note",
    Severity.LOW: "note",
}

# Findings with these statuses are not reported as code-scanning results.
_OMIT = {FindingStatus.SKIPPED_BUDGET, FindingStatus.ERROR}

# status -> SARIF level
_LEVEL = {
    FindingStatus.CONFIRMED: "error",
    FindingStatus.NOT_CONFIRMED: "note",
    FindingStatus.HARNESS_FAILED: "note",
}


def _fingerprint(rule_id: str, file: str, line: int) -> str:
    return hashlib.sha256(f"{rule_id}:{file}:{line}".encode()).hexdigest()[:16]


def build_sarif(report: RunReport) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for r in report.results:
        if r.status in _OMIT:
            continue
        f = r.finding
        uri = f.file.as_posix()
        level = _LEVEL.get(r.status, "note")

        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.vuln_class or f.rule_id},
                "defaultConfiguration": {"level": level},
                "helpUri": INFORMATION_URI,
            },
        )

        text = f.message
        if r.status == FindingStatus.CONFIRMED and r.crashes:
            c = r.crashes[0]
            text = (
                f"CONFIRMED: {f.message} "
                f"Reproduced {c.kind} at {c.sink_location or '?'} ({c.reproduced}x)."
            )
        elif r.status == FindingStatus.NOT_CONFIRMED:
            text = f"SAST flagged (not confirmed by fuzzing within budget): {f.message}"
        elif r.status == FindingStatus.HARNESS_FAILED:
            text = f"SAST flagged (no working harness produced): {f.message}"

        result: dict = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": max(1, f.line)},
                    }
                }
            ],
            "partialFingerprints": {
                "proofhound/v1": _fingerprint(f.rule_id, uri, f.line),
            },
        }
        if r.confidence is not None:
            result["properties"] = {"confidence": r.confidence}
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ProofHound",
                        "version": report.tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def build_sarif_from_findings(findings: Iterable[Finding], tool_version: str) -> dict:
    """SARIF for SAST-only findings (the `analyze` command) — no fuzzing confirmation.

    Severity maps to warning/note; nothing is reported as error because nothing is proven.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        uri = f.file.as_posix()
        level = _SEVERITY_LEVEL.get(f.severity, "note")
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.vuln_class or f.rule_id},
                "defaultConfiguration": {"level": level},
                "helpUri": INFORMATION_URI,
            },
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {
                    "proofhound/v1": _fingerprint(f.rule_id, uri, f.line),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ProofHound",
                        "version": tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _write(doc: dict, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return len(doc["runs"][0]["results"])


def write_sarif(report: RunReport, path: Path) -> int:
    """Write a scan RunReport as SARIF to `path`. Returns the number of results written."""
    return _write(build_sarif(report), path)


def write_sarif_findings(findings: Iterable[Finding], tool_version: str, path: Path) -> int:
    """Write SAST-only findings as SARIF to `path`. Returns the number of results written."""
    return _write(build_sarif_from_findings(findings, tool_version), path)
