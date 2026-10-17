"""Generate verified training data (distillation) for the Harness model.

Builds SecBench.js cases as split="train", runs the real pipeline on each with a large model, and
logs every harness attempt. train_local.py later keeps only attempts whose harness reached its
target, so every training example has passed the same execution checks as the benchmark.

    python training/generate_distillation.py --max-cases 3        # smoke test
    python training/generate_distillation.py                      # full run (resumable)
    python training/generate_distillation.py --shard 0/2          # two terminals in parallel:
    python training/generate_distillation.py --shard 1/2

No leakage: every package that appears in the evaluation benchmark is excluded, in any version
and any vulnerability class. Classes are interleaved (command-injection first, matching the
benchmark) so a partial run is still balanced.

Per case: build (npm in Docker) -> Analyzer -> the SAST finding at the ground-truth sink (else the
highest-severity finding) -> HarnessAgent (generate, verify, repair) -> fuzz if it reached.
Progress goes to distill_progress_<shard>.jsonl and finished cases are skipped on a rerun. The
run stops cleanly, without marking the case done, when every API key is out of quota or when
--max-tokens is spent.
"""

import argparse
import itertools
import json
import random
import time
from pathlib import Path

import yaml

CLASS_ORDER = ("command-injection", "path-traversal", "code-injection", "prototype-pollution", "redos")


def eval_packages(benchmark_cases: Path) -> set[str]:
    return {
        yaml.safe_load(p.read_text(encoding="utf-8"))["package"]
        for p in benchmark_cases.glob("*/case.yaml")
    }


def candidates(secbench: Path, classes: list[str], seed: int) -> list[tuple[str, str]]:
    """(class, case id) pairs, shuffled within a class and interleaved across classes."""
    per_class = []
    for vuln_class in classes:
        ids = sorted(
            d.name for d in (secbench / vuln_class).iterdir()
            if d.is_dir() and (d / "package.json").exists() and any(d.glob("*.test.js"))
        )
        random.Random(seed).shuffle(ids)
        per_class.append([(vuln_class, i) for i in ids])
    return [pair for row in itertools.zip_longest(*per_class) for pair in row if pair]


def pick_finding(findings: list, sink: str, tolerance: int):
    sink_file, sink_line, _ = sink.rsplit(":", 2)
    at_sink = [
        f for f in findings
        if f.file.as_posix() == sink_file and abs(f.line - int(sink_line)) <= tolerance
    ]
    if at_sink:
        return at_sink[0], True
    return (findings[0], False) if findings else (None, False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--secbench", type=Path, default=Path("vendor/SecBench.js"))
    ap.add_argument("--benchmark", type=Path, default=Path("benchmark/cases"),
                    help="Evaluation cases; their packages are excluded.")
    ap.add_argument("--cases-dir", type=Path, default=Path("training/cases"))
    ap.add_argument("--data-dir", type=Path, default=Path("training/data"))
    ap.add_argument("--config", type=Path, default=Path("configs/default.yaml"))
    ap.add_argument("--model", default="codecraft-claude", help="Model key from the config.")
    ap.add_argument("--classes", nargs="+", default=list(CLASS_ORDER))
    ap.add_argument("--max-cases", type=int, default=None, help="Process at most N new cases.")
    ap.add_argument("--max-tokens", type=int, default=None, help="Stop after spending this many tokens.")
    ap.add_argument("--shard", default="0/1", help="K/N: take every N-th candidate starting at K.")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-fuzz", action="store_true", help="Skip crash confirmation of reached harnesses.")
    args = ap.parse_args()

    from dotenv import load_dotenv

    load_dotenv(override=True)

    from proofhound.adapters.javascript import JavaScriptAdapter
    from proofhound.agents.analyzer import AnalyzeJob, AnalyzerAgent
    from proofhound.agents.fuzzer import FuzzerAgent, FuzzJob
    from proofhound.agents.harness import HarnessAgent
    from proofhound.benchmark.runner import LINE_TOLERANCE
    from proofhound.benchmark.secbench import build_case, load_case
    from proofhound.config import load_settings
    from proofhound.datalog.logger import AttemptLogger
    from proofhound.llm.client import build_client, is_quota_error
    from proofhound.sandbox.docker_runner import DockerSandbox
    from proofhound.sast.semgrep import SemgrepEngine

    shard, shards = (int(x) for x in args.shard.split("/"))
    tag = f"{shard}of{shards}"
    settings = load_settings(args.config)
    model_cfg = settings.models[args.model]
    args.data_dir.mkdir(parents=True, exist_ok=True)
    progress_path = args.data_dir / f"distill_progress_{tag}.jsonl"
    logger = AttemptLogger(args.data_dir / f"distill_attempts_{tag}.jsonl")

    done = {
        json.loads(line)["case"]
        for p in args.data_dir.glob("distill_progress_*.jsonl")
        for line in p.read_text(encoding="utf-8").splitlines() if line.strip()
    }
    excluded = eval_packages(args.benchmark)
    todo = [c for i, c in enumerate(candidates(args.secbench, args.classes, args.seed)) if i % shards == shard]
    todo = [c for c in todo if c[1] not in done]
    print(f"shard {tag}: {len(todo)} candidate cases left ({len(done)} done overall); "
          f"{len(excluded)} evaluation packages excluded; model {args.model}")

    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir)
    agent = HarnessAgent(
        client=build_client(args.model, model_cfg), model=model_cfg.model or args.model,
        adapter=adapter, sandbox=sandbox, settings=settings.harness, logger=logger,
    )
    fuzzer = FuzzerAgent(sandbox, adapter, attempt_logger=logger)

    def record(entry: dict) -> None:
        with progress_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  -> {entry['status']}" + (f" ({entry['detail']})" if entry.get("detail") else ""))

    processed = reached = 0
    for vuln_class, case_id in todo:
        if args.max_cases is not None and processed >= args.max_cases:
            break
        if args.max_tokens is not None and agent.tokens_used >= args.max_tokens:
            print(f"token budget reached ({agent.tokens_used:,}); stopping")
            break
        start = time.monotonic()
        base = {"case": case_id, "class": vuln_class}
        print(f"[{processed + 1}] {vuln_class}/{case_id}")
        try:
            case = load_case(args.secbench, vuln_class, case_id)
        except Exception as e:
            record({**base, "status": "metadata_error", "detail": f"{type(e).__name__}: {e}"[:200]})
            processed += 1
            continue
        if case.package in excluded:
            record({**base, "status": "excluded_eval_package", "package": case.package})
            continue

        dest = args.cases_dir / case_id
        try:
            if (dest / "case.yaml").exists() and (dest / "repo").exists():
                manifest = yaml.safe_load((dest / "case.yaml").read_text(encoding="utf-8"))
            else:
                manifest = build_case(case, dest, sandbox, split="train")
            analysis = analyzer.run(AnalyzeJob(dest / "repo", manifest["commit"]))
        except Exception as e:
            record({**base, "status": "build_or_analyze_error", "detail": f"{type(e).__name__}: {e}"[:200]})
            processed += 1
            continue

        finding, at_sink = pick_finding(analysis.findings, case.sink, LINE_TOLERANCE)
        if finding is None:
            record({**base, "status": "no_findings"})
            processed += 1
            continue

        out = dest / "out" / finding.id
        out.mkdir(parents=True, exist_ok=True)
        tokens_before = agent.tokens_used
        attempts_before = len(logger.read())
        try:
            harness = agent.produce(finding, dest / "repo", out)
            confirmed = False
            if harness is not None and not args.no_fuzz:
                job = FuzzJob(finding, dest / "repo", out, settings.budgets.fuzz_time_per_target_s)
                confirmed = bool(fuzzer.run(job).crashes)
        except Exception as e:
            if is_quota_error(e):
                print(f"every API key is out of quota ({e}); stopping — rerun later to resume")
                break
            record({**base, "status": "harness_error", "detail": f"{type(e).__name__}: {e}"[:200]})
            processed += 1
            continue

        processed += 1
        reached += harness is not None
        record({
            **base, "package": case.package, "finding": finding.id, "rule": finding.rule_id,
            "at_sink": at_sink, "status": "reached" if harness else "not_reached",
            "confirmed": confirmed, "attempts": len(logger.read()) - attempts_before,
            "tokens": agent.tokens_used - tokens_before, "seconds": round(time.monotonic() - start),
        })

    print(f"\nshard {tag}: processed {processed}, reached {reached}, tokens {agent.tokens_used:,}")
    print(f"attempts: {logger.path}   progress: {progress_path}")


if __name__ == "__main__":
    main()
