"""Term 1: one LLM proves vulnerabilities by driving every tool itself, in a single loop.

Each step the model sees the task and the history of its actions with their observations, and
answers with exactly one JSON action: {"thought": ..., "tool": ..., "args": {...}}. The protocol is
plain text on purpose — the same single-turn `complete()` call works for the Claude API and for the
local model, so neither backend is advantaged by a tool-calling format the other lacks. Replies that
break the protocol are counted (`protocol_errors`): that count is the tool-calling reliability
measure the comparison reports.

Whether a finding is proven comes from the tools (reached + confirmed), never from the model's
claims.
"""

import json
import re
from dataclasses import dataclass, field
from importlib import resources

from proofhound.core.budget import Budget
from proofhound.core.llm.client import LLMClient
from proofhound.single_agent.tools import TOOL_SPECS, AgentTools, FindingOutcome

RECENT_OBSERVATIONS = 3  # shown in full; older ones are shortened
FULL_OBSERVATION_CHARS = 12_000
SHORT_OBSERVATION_CHARS = 1_500
_FENCE = re.compile(r"```(\w*)[ \t]*\n(.*?)(?:\n```|\Z)", re.DOTALL)
_TOOL_NAMES = {spec["name"] for spec in TOOL_SPECS}


@dataclass
class Step:
    number: int
    reply: str
    tool: str | None = None
    args: dict = field(default_factory=dict)
    thought: str = ""
    observation: str = ""
    protocol_error: bool = False
    tokens: int = 0


@dataclass
class SingleAgentResult:
    outcomes: list[FindingOutcome]
    steps: list[Step]
    stop_reason: str  # finished | max_steps | budget
    tokens_used: int = 0

    @property
    def protocol_errors(self) -> int:
        return sum(s.protocol_error for s in self.steps)

    @property
    def proven(self) -> list[FindingOutcome]:
        return [o for o in self.outcomes if o.proven]


class SingleAgent:
    def __init__(
        self, client: LLMClient, tools: AgentTools, system_prompt: str, budget: Budget,
        task: str, max_steps: int = 30,
    ):
        self.client = client
        self.tools = tools
        self.system_prompt = system_prompt
        self.budget = budget
        self.task = task
        self.max_steps = max_steps

    def run(self) -> SingleAgentResult:
        steps: list[Step] = []
        stop_reason = "max_steps"
        for number in range(1, self.max_steps + 1):
            if self.budget.exhausted:
                stop_reason = "budget"
                break
            completion = self.client.complete(self.system_prompt, self._prompt(steps))
            self.budget.charge(completion.tokens_used)
            step = Step(number=number, reply=completion.text, tokens=completion.tokens_used)
            steps.append(step)
            action = parse_action(completion.text)
            if isinstance(action, str):
                step.protocol_error = True
                step.observation = json.dumps({"error": action})
                continue
            step.thought, step.tool, step.args = action
            if step.tool == "finish":
                stop_reason = "finished"
                break
            step.observation = json.dumps(self._dispatch(step.tool, step.args), default=str)
        return SingleAgentResult(
            outcomes=list(self.tools.outcomes.values()), steps=steps, stop_reason=stop_reason,
            tokens_used=self.budget.tokens_used,
        )

    def _dispatch(self, tool: str, args: dict) -> dict:
        try:
            return getattr(self.tools, tool)(**args)
        except TypeError as e:  # wrong or missing arguments
            return {"error": f"bad arguments for {tool}: {e}"}
        except Exception as e:  # an infrastructure failure is reported to the model, not raised
            return {"error": f"{tool} failed: {type(e).__name__}: {str(e)[:500]}"}

    def _prompt(self, steps: list[Step]) -> str:
        parts = [f"Task: {self.task}"]
        if self.tools.outcomes:  # kept in view so old, shortened observations need not be re-fetched
            parts.append("Findings so far:\n" + "\n".join(
                _status_line(o) for o in self.tools.outcomes.values()
            ))
        recent = {s.number for s in steps[-RECENT_OBSERVATIONS:]}
        for s in steps:
            limit = FULL_OBSERVATION_CHARS if s.number in recent else SHORT_OBSERVATION_CHARS
            action = (
                json.dumps({"tool": s.tool, "args": _abridged(s.tool, s.args)})
                if s.tool else "(reply did not follow the protocol)"
            )
            parts.append(
                f"Step {s.number}\nAction: {action}\nObservation: {_truncate(s.observation, limit)}"
            )
        parts.append(f"Budget left: {self.max_steps - len(steps)} step(s). Reply with the next action.")
        return "\n\n".join(parts)


def parse_action(reply: str) -> tuple[str, str, dict] | str:
    """(thought, tool, args) from a reply, or an error message telling the model what to fix.

    The JSON object may be bare or fenced. For write_harness, the code may come in a separate
    ```javascript block instead of `args.code` (models write code more reliably that way)."""
    blocks = _FENCE.findall(reply)
    json_text = next((body for lang, body in blocks if lang.lower() == "json"), None)
    candidate = json_text if json_text is not None else reply
    start = candidate.find("{")
    if start == -1:
        return 'no JSON action found; reply with one object: {"thought": ..., "tool": ..., "args": {...}}'
    try:
        obj, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as e:
        return f"the action is not valid JSON ({e.msg}); reply with exactly one JSON object"
    if not isinstance(obj, dict) or not isinstance(obj.get("tool"), str):
        return 'the action must be an object with a "tool" string'
    tool, args = obj["tool"], obj.get("args") or {}
    if tool not in _TOOL_NAMES:
        return f"unknown tool {tool!r}; choose one of: {', '.join(sorted(_TOOL_NAMES))}"
    if not isinstance(args, dict):
        return '"args" must be an object'
    if tool == "write_harness" and not args.get("code"):
        code = next((body for lang, body in blocks if lang.lower() in {"javascript", "js"}), None)
        if code is None:
            return "write_harness needs the harness code in args.code or in a ```javascript block"
        args = {**args, "code": code}
    return str(obj.get("thought", "")), tool, args


def load_system_prompt(adapter_template: str) -> tuple[str, str]:
    """(prompt version, system prompt) with the tool list and harness template filled in."""
    text = resources.files("proofhound.single_agent").joinpath("prompts/system.md").read_text("utf-8")
    version, _, body = text.partition("\n")
    tools = "\n".join(
        f"- {s['name']}: {s['description']} Args: {json.dumps(s['args']) if s['args'] else 'none'}"
        for s in TOOL_SPECS
    )
    return version.strip(), body.replace("{tools}", tools).replace("{harness_template}", adapter_template)


def _status_line(o: FindingOutcome) -> str:
    f = o.finding
    status = (
        "PROVEN" if o.proven else "reached, no crash confirmed yet" if o.reached
        else "harness not reaching the target yet" if o.harness_written else "not attempted"
    )
    where = f"{f.function.name} at {f.file.as_posix()}:{f.line}" if f.function else f"{f.file.as_posix()}:{f.line}"
    return f"- {f.id}: {where} [{f.vuln_class}] — {status}"


def _abridged(tool: str | None, args: dict) -> dict:
    """Keep the history short: a saved harness is on disk, so its code is not repeated."""
    if tool == "write_harness" and "code" in args:
        return {**args, "code": f"<{args['code'].count(chr(10)) + 1} lines saved>"}
    return args


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"... [{len(text) - limit} more characters]"
