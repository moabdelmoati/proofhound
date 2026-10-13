"""Runs Jazzer.js in the sandbox, monitors coverage and crashes, and updates the corpus."""

from proofhound.agents.base import Agent
from proofhound.models import Crash, Harness


class FuzzerAgent(Agent[Harness, list[Crash]]):
    name = "fuzzer"

    def run(self, data: Harness) -> list[Crash]:
        raise NotImplementedError
