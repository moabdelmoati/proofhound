"""Deduplicates crashes, fuses SAST and fuzzing evidence, generates the PoV, estimates CVSS."""

from proofhound.agents.base import Agent
from proofhound.models import Crash, TriageResult


class TriageAgent(Agent[list[Crash], list[TriageResult]]):
    name = "triage"

    def run(self, data: list[Crash]) -> list[TriageResult]:
        raise NotImplementedError
