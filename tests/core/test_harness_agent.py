from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.config import HarnessSettings
from proofhound.core.datalog.logger import AttemptLogger
from proofhound.core.fuzzing.sandbox import SandboxResult
from proofhound.core.harness.agent import HarnessAgent
from proofhound.core.llm.client import FakeClient
from proofhound.core.models import ChangedFunction, Finding, Severity


class FakeSandbox:
    def __init__(self, coverage_hits: list[int]):
        self.coverage_hits = iter(coverage_hits)
        self.coverage_report_existed: list[bool] = []

    def run(self, command, target, out, timeout_s, image=None, network=False):
        if command[:2] == ["node", "--check"]:
            return SandboxResult(0, "", False, 0.01)
        if "--coverage" in command:
            report = out / "coverage" / "coverage-final.json"
            self.coverage_report_existed.append(report.exists())
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(str(next(self.coverage_hits)), encoding="utf-8")
            return SandboxResult(0, "", False, 0.01)
        return SandboxResult(0, "", False, 0.01)


class HitAdapter(JavaScriptAdapter):
    def function_hits(self, out, fn):
        report = out / "coverage" / "coverage-final.json"
        return int(report.read_text(encoding="utf-8")) if report.exists() else None


def _finding() -> Finding:
    return Finding(
        id="finding-1", rule_id="proofhound.js.command-injection", severity=Severity.HIGH,
        message="Untrusted input reaches a shell", file=Path("lib/target.js"), line=1,
        source="input", sink="exec(input)", vuln_class="command-injection",
        function=ChangedFunction(
            file=Path("lib/target.js"), name="run", start_line=1, end_line=3,
            language="javascript",
        ),
    )


def test_harness_agent_repairs_and_discards_stale_coverage(tmp_path):
    target = tmp_path / "repo"
    (target / "lib").mkdir(parents=True)
    (target / "lib/target.js").write_text(
        "module.exports.run = (input) => input;\n", encoding="utf-8"
    )
    out = tmp_path / "out"
    out.mkdir()
    logger = AttemptLogger(tmp_path / "attempts.jsonl")
    client = FakeClient(replies=[
        "```javascript\nmodule.exports.fuzz = () => {};\n```",
        "module.exports.fuzz = () => {};",
    ])
    sandbox = FakeSandbox([0, 4])
    agent = HarnessAgent(
        client, "fake-model", HitAdapter(), sandbox,
        HarnessSettings(probe_time_s=1, large_model_repair_attempts=1), logger,
    )

    harness = agent.produce(_finding(), target, out)

    assert harness is not None
    assert harness.attempts == 2
    assert harness.compiled and harness.reached_target
    assert agent.tokens_used > 0
    assert sandbox.coverage_report_existed == [False, False]
    [first, second] = logger.read()
    assert first.failed_stage == "reach"
    assert not first.reached and second.reached and second.coverage_gain
    assert "previous harness failed" in client.prompts[1]
    assert (out / "harness.js").read_text(encoding="utf-8").startswith("module.exports")


def test_harness_agent_creates_corpus_dir_before_probe(tmp_path):
    # Regression: Jazzer.js requires the corpus directory to exist, so produce() must create it
    # before the probe fuzz run. Without it every probe failed with "required directory does not
    # exist" and no harness ever validated.
    target = tmp_path / "repo"
    (target / "lib").mkdir(parents=True)
    (target / "lib/target.js").write_text("module.exports.run = () => {};", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()

    corpus_present_at_probe: list[bool] = []

    class ProbeSpySandbox(FakeSandbox):
        def run(self, command, target, out, timeout_s, image=None, network=False):
            if "corpus" in " ".join(command) and command[:2] != ["node", "--check"]:
                corpus_present_at_probe.append((out / "corpus").is_dir())
            return super().run(command, target, out, timeout_s, image, network)

    agent = HarnessAgent(
        FakeClient(replies=["module.exports.fuzz = () => {};"]), "fake-model", HitAdapter(),
        ProbeSpySandbox([4]),
        HarnessSettings(probe_time_s=1, large_model_repair_attempts=0),
        AttemptLogger(tmp_path / "attempts.jsonl"),
    )
    agent.produce(_finding(), target, out)
    assert corpus_present_at_probe and all(corpus_present_at_probe)


def test_harness_agent_rejects_probe_timeout_and_logs_attempt(tmp_path):
    target = tmp_path / "repo"
    (target / "lib").mkdir(parents=True)
    (target / "lib/target.js").write_text("module.exports.run = () => {};", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    logger = AttemptLogger(tmp_path / "attempts.jsonl")

    class TimeoutSandbox(FakeSandbox):
        def run(self, command, target, out, timeout_s, image=None, network=False):
            if command[:2] == ["node", "--check"]:
                return SandboxResult(0, "", False, 0.01)
            return SandboxResult(-1, "timed out", True, timeout_s)

    client = FakeClient(replies=["module.exports.fuzz = () => {};"])
    agent = HarnessAgent(
        client, "fake-model", HitAdapter(), TimeoutSandbox([]),
        HarnessSettings(probe_time_s=1, large_model_repair_attempts=0), logger,
    )

    assert agent.produce(_finding(), target, out) is None
    [record] = logger.read()
    assert record.failed_stage == "probe"
    assert not record.loaded and not record.reached
