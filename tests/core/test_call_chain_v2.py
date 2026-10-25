from pathlib import Path
from proofhound.core.analysis.call_chain import extract_call_chain
from proofhound.core.models import Finding, ChangedFunction, Severity


def test_call_chain_v2_formatting():
    repo = Path("benchmark/cases/arpping_2.0.0/repo")
    if not repo.is_dir():
        return
    fn = ChangedFunction(
        file=Path("index.js"),
        name="Arpping.prototype.ping",
        start_line=109,
        end_line=129,
        language="javascript",
    )
    finding = Finding(
        id="c78059d5ac",
        rule_id="command-injection",
        severity=Severity.CRITICAL,
        message="command injection",
        file=Path("index.js"),
        line=120,
        sink="exec",
        vuln_class="command-injection",
        function=fn,
    )

    v2 = extract_call_chain(repo, finding, v2=True)
    assert "Call chain:" in v2
    assert "ping(" in v2
    assert "range: array" in v2
    assert "precondition: Array.isArray(range)" in v2
    assert "exec(" in v2
    assert "sink" in v2

    v1 = extract_call_chain(repo, finding, v2=False)
    assert "Call chain to reach the sink" in v1
