"""Rule-based: orders targets by severity and assigns fuzzing time; reuses the stored corpus."""

from proofhound.agents.base import Agent
from proofhound.models import Finding


class SchedulerAgent(Agent[list[Finding], list[Finding]]):
    name = "scheduler"

    def run(self, data: list[Finding]) -> list[Finding]:
        raise NotImplementedError
