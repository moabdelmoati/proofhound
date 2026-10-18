"""Proposes a patch and regression test; accepts it only if the PoV stops crashing and tests pass."""

from proofhound.core.agent import Agent
from proofhound.core.models import Patch, TriageResult


class PatcherAgent(Agent[TriageResult, Patch]):
    name = "patcher"

    def run(self, data: TriageResult) -> Patch:
        raise NotImplementedError
