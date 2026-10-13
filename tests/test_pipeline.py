from pathlib import Path

import yaml

from proofhound.agents.analyzer import Analysis
from proofhound.benchmark.runner import score_sast
from proofhound.config import Settings
from proofhound.datalog.logger import AttemptLogger, AttemptRecord
from proofhound.models import (
    ChangedFunction,
    Finding,
    FindingResult,
    FindingStatus,
    RunReport,
    Severity,
)
from proofhound.orchestrator.pipeline import Pipeline
from proofhound.reporting.json_report import read_json_report, write_json_report


def _finding(line: int, fid: str) -> Finding:
    fn = ChangedFunction(file=Path("lib/a.js"), name="f", start_line=1, end_line=99,
                         language="javascript")
    return Finding(id=fid, rule_id="r", severity=Severity.HIGH, message="", file=Path("lib/a.js"),
                   line=line, function=fn)


class FakeAnalyzer:
    def __init__(self, findings):
        self.findings = findings

    def run(self, job):
        return Analysis([], self.findings, len(self.findings))


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case1"
    (case / "repo").mkdir(parents=True)
    (case / "case.yaml").write_text(yaml.safe_dump({
        "id": "case1", "vuln_class": "command-injection", "commit_mode": "fixed",
        "sink": "lib/a.js:40:5", "commit": "abc",
    }))
    return case


def test_score_sast_hit_and_false_positives(tmp_path):
    result = score_sast(FakeAnalyzer([_finding(41, "a"), _finding(10, "b")]), _case(tmp_path))
    assert result.detected
    assert result.findings == 2
    assert result.false_positives == 1


def test_score_sast_miss(tmp_path):
    result = score_sast(FakeAnalyzer([_finding(10, "b")]), _case(tmp_path))
    assert not result.detected
    assert result.false_positives == 1


def test_report_roundtrip(tmp_path):
    report = RunReport(tool_version="0", repo="r", commit="c", started_at="t",
                       results=[FindingResult(finding=_finding(1, "a"),
                                              status=FindingStatus.CONFIRMED)])
    path = write_json_report(report, tmp_path)
    loaded = read_json_report(path)
    assert loaded.count(FindingStatus.CONFIRMED) == 1


def test_attempt_logger_marks_last_attempt(tmp_path):
    log = AttemptLogger(tmp_path / "a.jsonl")
    for attempt in (1, 2):
        log.log(AttemptRecord(case="c", split="train", finding_id="f", vuln_class=None,
                              attempt=attempt, model="m", prompt_version="v1", prompt="p",
                              output="o"))
    log.mark_crash_confirmed("f")
    records = log.read()
    assert [r.crash_confirmed for r in records] == [False, True]


def test_pipeline_charges_harness_tokens_when_production_raises(tmp_path):
    class RaisingHarness:
        tokens_used = 0

        def produce(self, finding, target, out):
            self.tokens_used += 17
            raise RuntimeError("sandbox unavailable")

    pipeline = Pipeline(Settings(), FakeAnalyzer([_finding(1, "a")]), RaisingHarness(), None, None)
    report = pipeline.run(tmp_path, "commit", tmp_path / "run")

    assert report.tokens_used == 17
    assert report.results[0].tokens_used == 17


def test_fusion_confirmed_class_match_is_high():
    from proofhound.agents.triage import fuse
    from proofhound.models import Crash, FindingStatus, Severity

    crash = Crash(finding_id="f", kind="Command Injection", input_path=Path("x"),
                  stack_trace="", signature="s", sink_location="a.js:1:1", reproduced=3)
    result = fuse(Severity.HIGH, "command-injection", FindingStatus.CONFIRMED, [crash], 30)
    assert result.confidence >= 0.9


def test_fusion_not_confirmed_lowers_prior():
    from proofhound.agents.triage import fuse
    from proofhound.models import FindingStatus, Severity

    result = fuse(Severity.HIGH, "command-injection", FindingStatus.NOT_CONFIRMED, [], 30)
    assert result.confidence < 0.45


def test_fusion_class_mismatch_is_medium():
    from proofhound.agents.triage import fuse
    from proofhound.models import Crash, FindingStatus, Severity

    crash = Crash(finding_id="f", kind="Prototype Pollution", input_path=Path("x"),
                  stack_trace="", signature="s", sink_location="a.js:1:1", reproduced=3)
    result = fuse(Severity.HIGH, "command-injection", FindingStatus.CONFIRMED, [crash], 30)
    assert 0.5 < result.confidence < 0.9
