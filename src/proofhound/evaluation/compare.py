"""Compare harness models end to end on pre-built benchmark cases (requires Docker).

    proofhound compare-models --model local-harness --model codecraft-claude --out runs/compare
    # one process per model runs them in parallel:
    python -m proofhound.evaluation.compare --models local-harness --out runs/compare-local
    python -m proofhound.evaluation.compare --models codecraft-claude --out runs/compare-claude

The Analyzer runs once per case. For every SAST finding in a changed function each model gets the
full HarnessAgent loop (generate, syntax, probe, coverage, repairs); a harness that reaches its
target is then fuzzed to see whether the vulnerability is confirmed. A finding counts at the best
stage any of its attempts reached. Sandbox failures are reported as errors, not model failures.

Writes <out>/summary.json (overall and per-vulnerability-class rows plus per-finding records) and
<out>/attempts_<model>.jsonl.
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

STAGES = ("syntax_ok", "loaded", "reached", "confirmed")


@dataclass
class Tally:
    findings: int = 0
    errors: int = 0
    syntax_ok: int = 0
    loaded: int = 0
    reached: int = 0
    confirmed: int = 0
    tokens: int = 0
    seconds: float = 0.0

    def add(self, record: dict) -> None:
        self.findings += 1
        for stage in STAGES:
            setattr(self, stage, getattr(self, stage) + int(record[stage]))
        self.tokens += record["tokens"]
        self.seconds += record["seconds"]

    def row(self, **labels) -> dict:
        pct = lambda n: f"{n} ({100 * n / self.findings:.0f}%)" if self.findings else "-"  # noqa: E731
        return {
            **labels, "findings": self.findings, "errors": self.errors,
            **{stage: pct(getattr(self, stage)) for stage in STAGES},
            "avg_tokens": self.tokens // max(self.findings, 1),
            "avg_seconds": round(self.seconds / max(self.findings, 1), 1),
        }


def _print_table(rows: list[dict]) -> None:
    if not rows:
        return
    keys = list(rows[0])
    widths = {k: max(len(k), *(len(str(r[k])) for r in rows)) for k in keys}
    print("  ".join(k.ljust(widths[k]) for k in keys))
    print("  ".join("-" * widths[k] for k in keys))
    for r in rows:
        print("  ".join(str(r[k]).ljust(widths[k]) for k in keys))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", default="benchmark/cases", type=Path)
    ap.add_argument("--config", default="configs/default.yaml", type=Path)
    ap.add_argument("--models", nargs="+", required=True, help="Model keys from the config.")
    ap.add_argument("--out", default="runs/compare", type=Path)
    ap.add_argument("--max-cases", type=int, default=None, help="Only the first N cases (smoke test).")
    ap.add_argument("--no-fuzz", action="store_true", help="Stop at coverage; skip crash confirmation.")
    args = ap.parse_args(argv)

    from dotenv import load_dotenv

    load_dotenv(override=True)  # .env wins over stale keys in the OS environment

    from proofhound.core.adapters.javascript import JavaScriptAdapter
    from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
    from proofhound.core.analysis.semgrep import SemgrepEngine
    from proofhound.core.config import load_settings
    from proofhound.core.datalog.logger import AttemptLogger
    from proofhound.core.fuzzing.fuzzer import FuzzerAgent, FuzzJob
    from proofhound.core.fuzzing.sandbox import DockerSandbox
    from proofhound.core.harness.agent import HarnessAgent
    from proofhound.core.llm.client import build_client

    settings = load_settings(args.config)
    missing = [k for k in args.models if k not in settings.models]
    if missing:
        sys.exit(f"unknown model(s) {missing}; available: {', '.join(settings.models)}")

    args.out.mkdir(parents=True, exist_ok=True)
    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir)
    agents, fuzzers, loggers = {}, {}, {}
    for key in args.models:
        cfg = settings.models[key]
        loggers[key] = AttemptLogger(args.out / f"attempts_{key}.jsonl")
        agents[key] = HarnessAgent(
            client=build_client(key, cfg), model=cfg.model or key, adapter=adapter,
            sandbox=sandbox, settings=settings.harness, logger=loggers[key],
        )
        fuzzers[key] = FuzzerAgent(sandbox, adapter, attempt_logger=loggers[key])

    case_dirs = sorted(
        d for d in args.cases.iterdir() if (d / "case.yaml").exists() and (d / "repo").exists()
    )[:args.max_cases]
    print(f"cases: {len(case_dirs)}  models: {args.models}  fuzz: {not args.no_fuzz}\n")

    overall = {k: Tally() for k in args.models}
    by_class: dict[tuple[str, str], Tally] = defaultdict(Tally)
    records: list[dict] = []

    for case_dir in case_dirs:
        manifest = yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))
        case_id, repo = manifest["id"], case_dir / "repo"
        try:
            analysis = analyzer.run(AnalyzeJob(repo, manifest["commit"]))
        except Exception as e:
            print(f"[{case_id}] analyzer error: {e}")
            continue
        print(f"[{case_id}] {len(analysis.findings)} finding(s)")

        for finding in analysis.findings:
            for key in args.models:
                out = args.out / case_id / finding.id / key
                out.mkdir(parents=True, exist_ok=True)
                before = len(loggers[key].read())
                start = time.monotonic()
                try:
                    harness = agents[key].produce(finding, repo, out)
                    confirmed = False
                    if harness is not None and not args.no_fuzz:
                        job = FuzzJob(finding, repo, out, settings.budgets.fuzz_time_per_target_s)
                        confirmed = bool(fuzzers[key].run(job).crashes)
                except Exception as e:
                    overall[key].errors += 1
                    print(f"  [{key}] error: {type(e).__name__}: {str(e)[:200]}")
                    continue
                attempts = loggers[key].read()[before:]
                record = {
                    "case": case_id, "finding_id": finding.id,
                    "vuln_class": finding.vuln_class or manifest["vuln_class"], "model": key,
                    "attempts": len(attempts),
                    "syntax_ok": any(a.syntax_ok for a in attempts),
                    "loaded": any(a.loaded for a in attempts),
                    "reached": any(a.reached for a in attempts),
                    "confirmed": confirmed,
                    "tokens": sum(a.input_tokens + a.output_tokens for a in attempts),
                    "seconds": round(time.monotonic() - start, 1),
                }
                records.append(record)
                overall[key].add(record)
                by_class[(key, record["vuln_class"])].add(record)
                best = next((s for s in reversed(STAGES) if record[s]), "failed")
                print(f"  [{key}] {best} in {record['attempts']} attempt(s) | "
                      f"{record['tokens']:,} tokens | {record['seconds']}s")

    rows = [overall[k].row(model=k) for k in args.models]
    class_rows = [t.row(model=k, vuln_class=c) for (k, c), t in sorted(by_class.items())]
    print("\n" + "=" * 80 + "\nSUMMARY\n" + "=" * 80)
    _print_table(rows)
    print()
    _print_table(class_rows)
    summary = args.out / "summary.json"
    summary.write_text(
        json.dumps({"models": rows, "by_class": class_rows, "per_finding": records}, indent=2),
        encoding="utf-8",
    )
    print(f"\n-> {summary}")


if __name__ == "__main__":
    main()
