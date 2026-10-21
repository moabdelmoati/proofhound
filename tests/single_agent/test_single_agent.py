"""The single agent: action protocol, the loop, tool gating, and what counts as proven."""

import json
from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.analyzer import Analysis
from proofhound.core.budget import Budget
from proofhound.core.fuzzing.fuzzer import FuzzOutcome
from proofhound.core.fuzzing.sandbox import SandboxResult
from proofhound.core.llm.client import FakeClient
from proofhound.core.models import ChangedFunction, Crash, Finding, FindingStatus, Severity
from proofhound.single_agent.agent import SingleAgent, load_system_prompt, parse_action
from proofhound.single_agent.runner import _finding_result
from proofhound.single_agent.tools import AgentTools, FindingOutcome

HARNESS = (
    'const { FuzzedDataProvider } = require("@jazzer.js/core");\n'
    'const target = require("/work/target/lib/target.js");\n'
    "module.exports.fuzz = function (data) {\n"
    "  target.run(new FuzzedDataProvider(data).consumeRemainingAsString());\n};"
)


def _finding() -> Finding:
    return Finding(
        id="f1", rule_id="proofhound.js.command-injection", severity=Severity.HIGH,
        message="Untrusted input reaches a shell", file=Path("lib/target.js"), line=2,
        source="cmd", sink="exec(cmd)", vuln_class="command-injection",
        function=ChangedFunction(file=Path("lib/target.js"), name="run", start_line=1,
                                 end_line=3, language="javascript"),
    )


def _action(tool: str, **args) -> str:
    return json.dumps({"thought": "t", "tool": tool, "args": args})


# --- protocol ---------------------------------------------------------------------------------

def test_parses_bare_json():
    assert parse_action(_action("run_sast")) == ("t", "run_sast", {})


def test_parses_fenced_json_with_surrounding_prose():
    reply = 'Let me look.\n```json\n{"thought": "x", "tool": "read_file", "args": {"path": "a.js"}}\n```'
    assert parse_action(reply) == ("x", "read_file", {"path": "a.js"})


def test_write_harness_takes_code_from_a_javascript_block():
    reply = _action("write_harness", finding_id="f1") + f"\n```javascript\n{HARNESS}\n```"
    _, tool, args = parse_action(reply)
    assert tool == "write_harness" and args["code"] == HARNESS


def test_protocol_errors_explain_the_fix():
    assert "no JSON action" in parse_action("I think the bug is in exec.")
    assert "not valid JSON" in parse_action('{"tool": "run_sast", "args": {')
    assert "unknown tool" in parse_action(_action("delete_repo"))
    assert "needs the harness code" in parse_action(_action("write_harness", finding_id="f1"))


def test_system_prompt_lists_every_tool_and_the_template():
    version, prompt = load_system_prompt("TEMPLATE-HERE")
    assert version == "single-agent-v1"
    for tool in ("run_sast", "write_harness", "check_harness", "run_fuzzer", "finish"):
        assert f"- {tool}:" in prompt
    assert "TEMPLATE-HERE" in prompt and "{tools}" not in prompt


# --- the loop ---------------------------------------------------------------------------------

class RecordingTools:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.outcomes: dict[str, FindingOutcome] = {}

    def run_sast(self):
        self.calls.append(("run_sast", {}))
        return {"findings": [{"finding_id": "f1"}]}

    def read_file(self, path):
        self.calls.append(("read_file", {"path": path}))
        return {"content": "x" * 50_000}


def _agent(replies, tools, max_steps=10, max_tokens=10**9):
    return SingleAgent(FakeClient(replies=list(replies)), tools, "system", Budget(900, max_tokens),
                       task="Prove it.", max_steps=max_steps)


def test_loop_dispatches_until_finish():
    tools = RecordingTools()
    result = _agent([_action("run_sast"), _action("read_file", path="a.js"),
                     _action("finish", summary="done")], tools).run()
    assert [c[0] for c in tools.calls] == ["run_sast", "read_file"]
    assert result.stop_reason == "finished" and len(result.steps) == 3
    assert result.protocol_errors == 0


def test_protocol_error_is_counted_and_fed_back():
    client_replies = ["not json", _action("finish", summary="")]
    agent = _agent(client_replies, RecordingTools())
    result = agent.run()
    assert result.protocol_errors == 1
    assert "no JSON action" in result.steps[0].observation
    assert "did not follow the protocol" in agent.client.prompts[1]


def test_bad_arguments_are_reported_not_raised():
    result = _agent([_action("read_file", wrong="x"), _action("finish", summary="")],
                    RecordingTools()).run()
    assert "bad arguments for read_file" in result.steps[0].observation


def test_stops_at_max_steps_and_on_budget():
    assert _agent([_action("run_sast")] * 5, RecordingTools(), max_steps=2).run().stop_reason == "max_steps"
    assert _agent([_action("run_sast")] * 5, RecordingTools(), max_tokens=1).run().stop_reason == "budget"


def test_findings_and_their_status_stay_in_view():
    tools = RecordingTools()
    tools.outcomes["f1"] = FindingOutcome(_finding(), harness_written=True, reached=True)
    agent = _agent([_action("finish", summary="")], tools)
    agent.run()
    assert "- f1: run at lib/target.js:2 [command-injection] — reached, no crash confirmed yet" \
        in agent.client.prompts[0]


def test_history_shortens_old_observations():
    tools = RecordingTools()
    replies = [_action("read_file", path="a.js")] + [_action("run_sast")] * 4 + [_action("finish", summary="")]
    agent = _agent(replies, tools)
    agent.run()
    last_prompt = agent.client.prompts[-1]
    assert "more characters]" in last_prompt and len(last_prompt) < 20_000


# --- tools: gating and proof ------------------------------------------------------------------

class FakeAnalyzer:
    def run(self, job):
        f = _finding()
        return Analysis(changed_functions=[f.function], findings=[f], all_sast_findings=3)


class FakeSandbox:
    def __init__(self, hits: int):
        self.hits = hits

    def run(self, command, target, out, timeout_s, image=None, network=False):
        if "--coverage" in command:
            report = out / "coverage" / "coverage-final.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(str(self.hits), encoding="utf-8")
        return SandboxResult(0, "", False, 0.01)


class HitAdapter(JavaScriptAdapter):
    def function_hits(self, out, fn):
        report = out / "coverage" / "coverage-final.json"
        return int(report.read_text(encoding="utf-8")) if report.exists() else None


class FakeFuzzer:
    def __init__(self, crash: bool, kind: str = "Command Injection"):
        self.crash = crash
        self.kind = kind

    def run(self, job):
        crashes = [Crash(finding_id=job.finding.id, kind=self.kind, input_path=Path("c"),
                         stack_trace="", signature="s", sink_location="lib/target.js:2:3",
                         reproduced=3)] if self.crash else []
        confirmed = self.crash and self.kind == "Command Injection"  # the finding is command injection
        return FuzzOutcome(crashes=crashes, confirmed=confirmed)


def _tools(tmp_path, hits=1, crash=True, kind="Command Injection") -> AgentTools:
    return AgentTools(repo=tmp_path, commit="abc", adapter=HitAdapter(), analyzer=FakeAnalyzer(),
                      sandbox=FakeSandbox(hits), fuzzer=FakeFuzzer(crash, kind), out=tmp_path / "out")


def test_fuzzer_is_refused_until_the_harness_reaches_the_target(tmp_path):
    tools = _tools(tmp_path, hits=0)
    tools.run_sast()
    tools.write_harness("f1", HARNESS)
    assert tools.check_harness("f1")["failed_stage"] == "reach"
    assert "has not reached" in tools.run_fuzzer("f1")["error"]
    assert not tools.outcomes["f1"].proven


def test_reached_and_confirmed_is_proven(tmp_path):
    tools = _tools(tmp_path)
    assert tools.run_sast()["findings"][0]["module_path"] == "/work/target/lib/target.js"
    tools.write_harness("f1", f"```javascript\n{HARNESS}\n```")
    assert (tmp_path / "out" / "f1" / "harness.js").read_text(encoding="utf-8") == HARNESS + "\n"
    assert tools.check_harness("f1")["reached"] is True
    assert tools.run_fuzzer("f1")["confirmed"] is True
    assert tools.outcomes["f1"].proven


def test_a_crash_of_another_class_does_not_prove_the_finding(tmp_path):
    tools = _tools(tmp_path, kind="Prototype Pollution")
    tools.run_sast()
    tools.write_harness("f1", HARNESS)
    tools.check_harness("f1")
    result = tools.run_fuzzer("f1")
    assert result["confirmed"] is False
    assert result["crashes"][0]["kind"] == "Prototype Pollution"  # still reported as evidence
    assert not tools.outcomes["f1"].proven
    assert _finding_result(tools.outcomes["f1"], "finished").status == FindingStatus.NOT_CONFIRMED


def test_rewriting_a_harness_keeps_an_earlier_proof_but_regates_the_fuzzer(tmp_path):
    tools = _tools(tmp_path)
    tools.run_sast()
    tools.write_harness("f1", HARNESS)
    tools.check_harness("f1")
    tools.run_fuzzer("f1")
    tools.write_harness("f1", HARNESS)
    assert tools.outcomes["f1"].proven
    assert "has not reached" in tools.run_fuzzer("f1")["error"]


def test_unknown_finding_and_missing_harness_are_errors(tmp_path):
    tools = _tools(tmp_path)
    assert "call run_sast first" in tools.write_harness("nope", HARNESS)["error"]
    tools.run_sast()
    assert "call write_harness first" in tools.check_harness("f1")["error"]


def test_read_file_cannot_escape_the_repository(tmp_path):
    assert "escapes" in _tools(tmp_path).read_file("../secret.txt")["error"]


# --- report mapping ---------------------------------------------------------------------------

def test_outcomes_map_to_the_shared_report_statuses():
    def status(stop="finished", **fields):
        return _finding_result(FindingOutcome(_finding(), **fields), stop).status

    crash = Crash(finding_id="f1", kind="Command Injection", input_path=Path("c"), stack_trace="",
                  signature="s")
    assert status(reached=True, crashes=[crash]) == FindingStatus.CONFIRMED
    assert status(reached=True) == FindingStatus.NOT_CONFIRMED
    assert status(harness_written=True) == FindingStatus.HARNESS_FAILED
    assert status("max_steps") == FindingStatus.SKIPPED_BUDGET
