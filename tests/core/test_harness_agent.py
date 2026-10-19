from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.config import HarnessSettings
from proofhound.core.datalog.logger import AttemptLogger
from proofhound.core.fuzzing.sandbox import SandboxResult
from proofhound.core.harness.agent import SINK_MARK, HarnessAgent, build_prompt
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
        "module.exports.fuzz = (data) => {};",
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
    assert "module.exports.fuzz = () => {};" in client.prompts[1]  # the repair sees its harness
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


def _agent(tmp_path, replies, sandbox, repairs):
    target = tmp_path / "repo"
    (target / "lib").mkdir(parents=True)
    (target / "lib/target.js").write_text("module.exports.run = () => {};", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    logger = AttemptLogger(tmp_path / "attempts.jsonl")
    client = FakeClient(replies=list(replies))
    agent = HarnessAgent(
        client, "fake-model", HitAdapter(), sandbox,
        HarnessSettings(probe_time_s=1, large_model_repair_attempts=repairs), logger,
    )
    return agent, client, logger, target, out


class CountingSandbox(FakeSandbox):
    def __init__(self, coverage_hits):
        super().__init__(coverage_hits)
        self.syntax_checks = 0

    def run(self, command, target, out, timeout_s, image=None, network=False):
        self.syntax_checks += command[:2] == ["node", "--check"]
        return super().run(command, target, out, timeout_s, image, network)


def test_replies_without_a_harness_skip_the_sandbox(tmp_path):
    echo = "Generate a harness...\nModule path inside the sandbox: /work/target/lib/target.js\n"
    sandbox = CountingSandbox([4])
    agent, client, logger, target, out = _agent(
        tmp_path, ["", echo, "module.exports.fuzz = () => {};"], sandbox, repairs=2,
    )

    harness = agent.produce(_finding(), target, out)

    assert harness is not None and harness.attempts == 3
    assert sandbox.syntax_checks == 1  # only the real harness was run
    empty, echoed, good = logger.read()
    assert empty.failed_stage == echoed.failed_stage == "no_harness"
    assert "repeated the prompt" in client.prompts[2]
    assert good.reached


def test_unchanged_repair_is_not_rerun(tmp_path):
    sandbox = CountingSandbox([0])
    agent, _client, logger, target, out = _agent(
        tmp_path, ["module.exports.fuzz = () => {};"] * 2, sandbox, repairs=1,
    )

    assert agent.produce(_finding(), target, out) is None
    assert sandbox.syntax_checks == 1
    first, second = logger.read()
    assert first.failed_stage == second.failed_stage == "reach"
    assert first.syntax_ok and second.syntax_ok and second.loaded


def test_prompt_names_and_marks_the_sink_line():
    finding = _finding().model_copy(update={"line": 2})
    source = "function run(input) {\n  exec(input);\n}"

    prompt = build_prompt(finding, source, source, "/work/target/lib/target.js", "template")
    unguided = build_prompt(finding, source, source, "/work/target/lib/target.js", "template", False)

    assert f"  exec(input);  {SINK_MARK}\n}}" in prompt
    assert "Sink line: 2" in prompt
    assert SINK_MARK not in unguided and "Sink line" not in unguided
