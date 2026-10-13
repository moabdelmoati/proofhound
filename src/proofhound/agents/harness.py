"""Writes a fuzz harness guided by the finding; feeds compile/runtime errors back for repair."""

from proofhound.agents.base import Agent
from proofhound.models import Finding, Harness


class HarnessAgent(Agent[Finding, Harness]):
    name = "harness"

    def run(self, data: Finding) -> Harness:
        raise NotImplementedError
