"""Deterministic tools the single agent (RQ3) is given.

These are thin wrappers over the same infrastructure the multi-agent pipeline uses, so the two
systems are compared on identical capabilities. None of these call an LLM; the agent loop that
calls the model and dispatches these tools lives in `single_agent.py`, and its prompt is a
separate file authored by the team.

Each tool takes JSON-serializable arguments and returns a JSON-serializable result, so it can be
exposed to any provider's tool/function-calling interface unchanged.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path

from proofhound.adapters.base import LanguageAdapter
from proofhound.agents.fuzzer import FuzzerAgent, FuzzJob
from proofhound.models import Finding
from proofhound.sast.base import SastEngine
from proofhound.vcs.diff import changed_lines


@dataclass
class AgentTools:
    repo: Path
    commit: str
    adapter: LanguageAdapter
    sast: SastEngine
    rules_dir: Path
    fuzzer: FuzzerAgent
    out: Path
    fuzz_time_s: int = 30
    max_file_bytes: int = 20_000

    def git_diff(self) -> dict:
        """Changed files and their added line numbers in the commit."""
        changed = changed_lines(self.repo, self.commit, self.adapter.extensions)
        return {str(f): sorted(lines) for f, lines in changed.items()}

    def read_file(self, path: str, start: int = 1, end: int | None = None) -> dict:
        """Read a file in the repo (optionally a line range), truncated to a byte cap."""
        target = (self.repo / path).resolve()
        if not str(target).startswith(str(self.repo.resolve())):
            return {"error": "path escapes the repository"}
        if not target.is_file():
            return {"error": "not a file"}
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        end = end or len(lines)
        selected = "\n".join(lines[start - 1:end])[: self.max_file_bytes]
        return {"path": path, "start": start, "end": end, "content": selected}

    def run_sast(self) -> list[dict]:
        """Run SAST on the changed files; return findings as plain dicts."""
        findings = self.sast.scan(list(self.git_diff()), self.rules_dir, root=self.repo)
        return [f.model_dump(mode="json") for f in findings]

    def write_harness(self, finding_id: str, code: str) -> dict:
        """Save a harness the agent wrote, so run_fuzzer can execute it."""
        (self.out / finding_id).mkdir(parents=True, exist_ok=True)
        (self.out / finding_id / "harness.js").write_text(code, encoding="utf-8")
        return {"saved": True, "finding_id": finding_id}

    def run_fuzzer(self, finding: dict) -> dict:
        """Fuzz the harness the agent saved for `finding` and report confirmed crashes."""
        f = Finding.model_validate(finding)
        job = FuzzJob(f, self.repo, self.out / f.id, self.fuzz_time_s)
        outcome = self.fuzzer.run(job)
        return {
            "confirmed": bool(outcome.crashes),
            "crashes": [c.model_dump(mode="json") for c in outcome.crashes],
            "other_reports": [r.kind for r in outcome.other_reports],
        }


# JSON-schema tool descriptions, provider-agnostic. The agent loop maps a tool call by `name`
# to the matching AgentTools method.
TOOL_SPECS = [
    {"name": "git_diff", "description": "List changed files and their added line numbers.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "read_file", "description": "Read a file (optionally a line range) from the repo.",
     "parameters": {"type": "object", "properties": {
         "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
         "required": ["path"]}},
    {"name": "run_sast", "description": "Run SAST on the changed files and return findings.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "write_harness", "description": "Save a fuzz harness for a finding.",
     "parameters": {"type": "object", "properties": {
         "finding_id": {"type": "string"}, "code": {"type": "string"}},
         "required": ["finding_id", "code"]}},
    {"name": "run_fuzzer", "description": "Fuzz the saved harness and report confirmed crashes.",
     "parameters": {"type": "object", "properties": {"finding": {"type": "object"}},
                    "required": ["finding"]}},
]
