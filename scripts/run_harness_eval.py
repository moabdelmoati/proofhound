import json
import re
import sys
from pathlib import Path
import yaml

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.core.analysis.semgrep import SemgrepEngine
from proofhound.core.config import load_settings
from proofhound.core.fuzzing.fuzzer import FuzzerAgent, FuzzJob
from proofhound.core.fuzzing.sandbox import DockerSandbox


def run_case_harness(case_name: str, finding_id: str, harness_code: str, time_s: int = 15):
    settings = load_settings(Path('configs/default.yaml'))
    sandbox = DockerSandbox(settings.sandbox)
    adapter = JavaScriptAdapter()
    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir)
    case_dir = Path(f'benchmark/cases/{case_name}')
    manifest = yaml.safe_load((case_dir / 'case.yaml').read_text(encoding='utf-8'))
    analysis = analyzer.run(AnalyzeJob(case_dir / 'repo', manifest['commit']))

    matching_findings = [f for f in analysis.findings if f.id == finding_id]
    if not matching_findings:
        print(f"Finding {finding_id} not found in {case_name}. Available: {[f.id for f in analysis.findings]}")
        return None, None
    finding = matching_findings[0]

    out_dir = Path(f'runs/test-{case_name}')
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'harness.js').write_text(harness_code, encoding='utf-8')

    fuzzer = FuzzerAgent(sandbox, adapter)
    job = FuzzJob(finding, case_dir / 'repo', out_dir, time_s=time_s)
    outcome = fuzzer.run(job)

    log_content = ""
    if (out_dir / 'fuzz.log').exists():
        log_content = (out_dir / 'fuzz.log').read_text(encoding='utf-8', errors='ignore')

    return outcome, log_content


if __name__ == '__main__':
    case_name = sys.argv[1]
    finding_id = sys.argv[2]
    harness_path = sys.argv[3]
    harness_code = Path(harness_path).read_text(encoding='utf-8')
    outcome, log_content = run_case_harness(case_name, finding_id, harness_code)
    print("Outcome confirmed:", outcome.confirmed)
    print("Crashes:", len(outcome.crashes))
    print("Other reports:", len(outcome.other_reports))
    for c in outcome.crashes:
        print("Crash:", c.kind, "reproduced:", c.reproduced)
    for r in outcome.other_reports:
        print("Report:", r.kind, r.crash_file)
    if "Command Injection" in log_content:
        print("Command Injection detector detected in log!")
    print("--- LOG PREVIEW ---")
    print(log_content[-2000:].encode('ascii', errors='replace').decode('ascii'))
