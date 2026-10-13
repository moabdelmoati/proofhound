"""Extracts changed functions from the diff and runs SAST on them."""

from proofhound.agents.base import Agent
from proofhound.models import Finding


class AnalyzerAgent(Agent[str, list[Finding]]):
    name = "analyzer"

    def run(self, data: str) -> list[Finding]:
        raise NotImplementedError
