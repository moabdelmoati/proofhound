from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.datalog.logger import AttemptLogger, AttemptRecord, case_id
from proofhound.core.fuzzing.fuzzer import FuzzerAgent, FuzzJob
from proofhound.core.fuzzing.sandbox import SandboxResult
from proofhound.core.models import ChangedFunction, Finding, Severity, kind_matches_class


def _jazzer(kind: str) -> str:
    return (f"==1== {kind}\n"
            "    at run (/work/target/lib/target.js:2:3)\n"
            "artifact_prefix='/work/out/'; Test unit written to /work/out/crash-abc\n")


class FakeSandbox:
    """Fuzz run and every replay report the same detector."""

    def __init__(self, kind: str):
        self.kind = kind

    def run(self, command, target, out, timeout_s, image=None, network=False):
        return SandboxResult(1, _jazzer(self.kind), False, 0.01)


def _finding(vuln_class: str) -> Finding:
    return Finding(
        id="f1", rule_id=f"proofhound.js.{vuln_class}", severity=Severity.HIGH, message="m",
        file=Path("lib/target.js"), line=2, vuln_class=vuln_class,
        function=ChangedFunction(file=Path("lib/target.js"), name="run", start_line=1, end_line=3,
                                 language="javascript"),
    )


def _fuzz(tmp_path, detector: str, vuln_class: str):
    log = AttemptLogger(tmp_path / "attempts.jsonl")
    case = tmp_path / "case" / "repo"
    log.log(AttemptRecord(case=case_id(case), split="eval", finding_id="f1", vuln_class=vuln_class,
                          attempt=1, model="m", prompt_version="v", prompt="p", output="o"))
    fuzzer = FuzzerAgent(FakeSandbox(detector), JavaScriptAdapter(), attempt_logger=log)
    outcome = fuzzer.run(FuzzJob(_finding(vuln_class), case, tmp_path / "out", 1))
    return outcome, log.read()[0].crash_confirmed


def test_matching_detector_confirms_the_finding(tmp_path):
    outcome, logged = _fuzz(tmp_path, "Command Injection", "command-injection")
    assert outcome.confirmed and logged
    assert [c.kind for c in outcome.crashes] == ["Command Injection"]


def test_other_detector_is_kept_as_evidence_but_does_not_confirm(tmp_path):
    outcome, logged = _fuzz(tmp_path, "Command Injection", "redos")
    assert not outcome.confirmed and not logged
    assert [c.kind for c in outcome.crashes] == ["Command Injection"]


def test_kind_matches_class():
    assert kind_matches_class("Command Injection", "command-injection")
    assert kind_matches_class("Path Traversal", "path-traversal")
    assert not kind_matches_class("Command Injection", "redos")
    assert not kind_matches_class("Prototype Pollution", "command-injection")
    assert kind_matches_class("Command Injection", None)  # no class to check against
