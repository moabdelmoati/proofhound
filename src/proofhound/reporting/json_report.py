"""Writes the full run result as JSON: runs/<commit>/report.json."""

from pathlib import Path

from proofhound.models import RunReport


def write_json_report(report: RunReport, run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def read_json_report(path: Path) -> RunReport:
    return RunReport.model_validate_json(path.read_text(encoding="utf-8"))
