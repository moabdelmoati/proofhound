from pathlib import Path

from proofhound.config import load_settings
from proofhound.models import Finding, Severity


def test_finding_roundtrip():
    f = Finding(
        id="f1",
        rule_id="js.command-injection",
        severity=Severity.HIGH,
        message="user input reaches child_process.exec",
        file=Path("src/index.js"),
        line=12,
        source="req.query.cmd",
        sink="child_process.exec",
    )
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_default_config_loads():
    settings = load_settings(Path(__file__).parents[1] / "configs" / "default.yaml")
    assert settings.language == "javascript"
    assert settings.sandbox.network == "none"
