"""Proposes a patch and regression test; accepts it only if the PoV stops crashing and tests pass."""

from proofhound.agents.base import Agent
from proofhound.models import Patch, TriageResult


class PatcherAgent(Agent[TriageResult, Patch]):
    name = "patcher"

    def run(self, data: TriageResult) -> Patch:
        raise NotImplementedError
