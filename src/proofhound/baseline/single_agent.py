"""Single-agent baseline (RQ3): one LLM with the same model, tools, budget, and report format.

The agent is given the tools in `tools.py` and asked, in one loop, to find and confirm a
vulnerability in the commit. This isolates the effect of the *architecture* (one general agent
vs. the specialized multi-agent pipeline) because both share the same tools and infrastructure.

This module provides the generic tool-use loop and result shaping. The system prompt that drives
the model is a separate file (`prompts/single_agent/system.md`) authored by the team, mirroring
how the Harness Agent's prompt is kept out of the code.
"""

from dataclasses import dataclass, field
from pathlib import Path

from proofhound.baseline.tools import TOOL_SPECS, AgentTools
from proofhound.llm.client import LLMClient
from proofhound.models import Crash
from proofhound.orchestrator.budget import Budget


@dataclass
class SingleAgentResult:
    confirmed: list[Crash] = field(default_factory=list)
    steps: int = 0
    tokens_used: int = 0
    transcript: list[dict] = field(default_factory=list)


class SingleAgent:
    def __init__(
        self,
        client: LLMClient,
        tools: AgentTools,
        system_prompt: str,
        budget: Budget,
        max_steps: int = 20,
    ):
        self.client = client
        self.tools = tools
        self.system_prompt = system_prompt
        self.budget = budget
        self.max_steps = max_steps

    def _dispatch(self, name: str, args: dict) -> object:
        method = {
            "git_diff": lambda: self.tools.git_diff(),
            "read_file": lambda: self.tools.read_file(**args),
            "run_sast": lambda: self.tools.run_sast(),
            "write_harness": lambda: self.tools.write_harness(**args),
            "run_fuzzer": lambda: self.tools.run_fuzzer(**args),
        }.get(name)
        if method is None:
            return {"error": f"unknown tool {name}"}
        try:
            return method()
        except Exception as e:  # noqa: BLE001 - tool errors are fed back to the model
            return {"error": f"{type(e).__name__}: {e}"}

    def run(self) -> SingleAgentResult:
        """Drive the model/tool loop until it confirms a crash or the budget/steps run out.

        The provider-specific wiring (how tool calls are represented in the request/response) is
        completed with the team's loop over `self.client` and `TOOL_SPECS`; `_dispatch` and the
        tools are provider-agnostic and ready to use.
        """
        raise NotImplementedError(
            "Wire the provider tool-call loop here; tools and dispatch are ready."
        )


def load_system_prompt(path: Path = Path("prompts/single_agent/system.md")) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


__all__ = ["SingleAgent", "SingleAgentResult", "AgentTools", "TOOL_SPECS", "load_system_prompt"]
