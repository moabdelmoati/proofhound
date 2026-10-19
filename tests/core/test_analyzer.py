from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis import analyzer
from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.core.models import Finding, Severity


class TwoTraceSast:
    """Semgrep reports one sink once per taint trace that reaches it."""

    def scan(self, files, rules_dir, root):
        finding = Finding(
            id="same-location", rule_id="proofhound.js.command-injection", severity=Severity.HIGH,
            message="m", file=Path("index.js"), line=2, source="cmd", sink="exec(cmd)",
        )
        return [finding, finding.model_copy(update={"source": "other"})]


def test_analyzer_keeps_one_finding_per_location(tmp_path, monkeypatch):
    (tmp_path / "index.js").write_text(
        "function run(cmd) {\n  require('child_process').exec(cmd);\n}\nmodule.exports = { run };\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(analyzer, "changed_lines", lambda repo, commit, ext: {Path("index.js"): {2}})

    result = AnalyzerAgent(JavaScriptAdapter(), TwoTraceSast(), tmp_path).run(AnalyzeJob(tmp_path))

    assert [f.id for f in result.findings] == ["same-location"]
    assert result.all_sast_findings == 2
