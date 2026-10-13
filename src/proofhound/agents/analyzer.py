"""Extracts changed functions from the diff and runs SAST on them.

Only findings that fall inside a function changed by the commit are kept, ordered by severity.
"""

from dataclasses import dataclass
from pathlib import Path

from proofhound.adapters.base import LanguageAdapter, innermost
from proofhound.agents.base import Agent
from proofhound.models import ChangedFunction, Finding, Severity
from proofhound.sast.base import SastEngine
from proofhound.vcs.diff import changed_lines

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


@dataclass
class AnalyzeJob:
    repo: Path
    commit: str = "HEAD"


@dataclass
class Analysis:
    changed_functions: list[ChangedFunction]
    findings: list[Finding]
    all_sast_findings: int  # before filtering to changed functions


class AnalyzerAgent(Agent[AnalyzeJob, Analysis]):
    name = "analyzer"

    def __init__(self, adapter: LanguageAdapter, sast: SastEngine, rules_dir: Path):
        self.adapter = adapter
        self.sast = sast
        self.rules_dir = rules_dir

    def run(self, data: AnalyzeJob) -> Analysis:
        changed = changed_lines(data.repo, data.commit, self.adapter.extensions)
        functions: list[ChangedFunction] = []
        for file, lines in changed.items():
            functions += self.adapter.extract_functions(file, lines, root=data.repo)

        raw = self.sast.scan(list(changed), self.rules_dir, root=data.repo)
        findings = []
        for finding in raw:
            in_file = [f for f in functions if f.file == finding.file]
            fn = innermost(in_file, finding.line)
            if fn is not None:
                findings.append(finding.model_copy(update={"function": fn}))
        findings.sort(key=lambda f: (_SEVERITY_ORDER.index(f.severity), str(f.file), f.line))
        return Analysis(functions, findings, len(raw))
