"""Build the v6 harness training set: one format, every source, prompts identical to inference.

    python scripts/build_training_v6.py

Why this exists: the v5 dataset was built with a hand-written prompt that the pipeline never
sends, and it replaced (rather than extended) the 108 examples the 7B was trained on. The 14B
trained on it regressed on cases the 7B already solved. This builder fixes both faults.

Every row is {prompt, completion, ...} where `prompt` is byte-for-byte what `HarnessAgent`
sends at inference time and `completion` is the harness source alone. The builder proves that
claim: for findings whose real prompt exists in a saved eval log it rebuilds the prompt and
aborts if the rebuild differs.

Sources merged:
  A  training/data/distill_attempts_*.jsonl + distill_progress_*.jsonl  (the original 108-example
     distillation; prompts are rebuilt in the current format, now including the v4 call chain)
  B  training/data/distill-v5/*.json                                    (Claude + Gemini trajectories)
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.call_chain import extract_call_chain
from proofhound.core.harness.agent import PROMPT_VERSION, build_prompt
from proofhound.core.models import Finding

DATA = Path("training/data")
TRAIN_CASES = Path("training/cases")
BENCH_CASES = Path("benchmark/cases")
# Saved eval logs used to prove the rebuilt prompts are what the pipeline really sends.
# Logs written before a prompt change no longer match current code; that is expected and
# reported, but at least one log must match or the build aborts.
EVAL_LOGS = [
    Path("runs/validate-14b-v5-3case/attempts_local-harness.jsonl"),
    Path("runs/smoke-14b-v5/attempts_local-harness.jsonl"),
    Path("runs/regression-14b-v5/attempts_local-harness.jsonl"),
    Path("runs/compare-v4-full/attempts_local-harness.jsonl"),
]


def case_split(case):
    for root in (TRAIN_CASES, BENCH_CASES):
        m = root / case / "case.yaml"
        if m.is_file():
            return yaml.safe_load(m.read_text(encoding="utf-8")).get("split")
    return None


def make_prompt(finding: Finding, repo: Path, adapter: JavaScriptAdapter) -> str | None:
    """Exactly what HarnessAgent.produce() builds. Keep in step with agent.py:76-86."""
    function = finding.function
    if function is None:
        return None
    source_path = repo / finding.file
    if not source_path.is_file():
        return None
    source = source_path.read_text(encoding="utf-8", errors="replace")
    lines = source.splitlines()
    function_source = "\n".join(lines[max(0, function.start_line - 1):function.end_line])
    module = f"/work/target/{finding.file.as_posix()}"
    template = adapter.harness_template(module=module)
    call_chain = extract_call_chain(repo, finding, v2=True)
    return build_prompt(finding, function_source, source, module, template, True,
                        call_chain=call_chain)


def strip_fence(text: str) -> str:
    """The harness source alone: drop prose and ``` fences the teacher wrapped it in."""
    if "```" not in text:
        return text.strip()
    blocks, rest = [], text
    while "```" in rest:
        _, _, rest = rest.partition("```")
        body, _, rest = rest.partition("```")
        if body.startswith(("javascript\n", "js\n")):
            body = body.split("\n", 1)[1]
        blocks.append(body.strip())
    return max(blocks, key=len) if blocks else text.strip()


def match_by_sink(findings: dict[str, Finding], sink: str | None,
                  vuln_class: str | None) -> Finding | None:
    """The finding at `sink` ("path/to/file.js:LINE[:COL]") in `vuln_class`, if exactly one."""
    if not sink or ":" not in sink:
        return None
    parts = sink.split(":")
    try:
        line = int(parts[1])
    except (IndexError, ValueError):
        return None
    wanted = parts[0].replace("\\", "/").lstrip("./")
    hits = [
        f for f in findings.values()
        if f.line == line
        and f.file.as_posix().replace("\\", "/").endswith(wanted)
        and (vuln_class is None or f.vuln_class == vuln_class)
    ]
    return hits[0] if len(hits) == 1 else None


def load_eval_prompts() -> dict[tuple[str, str], list[tuple[str, str]]]:
    """Real prompts the pipeline sent, keyed by (case, finding_id) -> [(log name, prompt)]."""
    out: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for log in EVAL_LOGS:
        if not log.is_file():
            continue
        for line in log.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            key = (r["case"], r["finding_id"])
            entries = out.setdefault(key, [])
            if not any(name == log.parent.name for name, _ in entries):
                entries.append((log.parent.name, r["prompt"]))
    return out


def source_a(adapter: JavaScriptAdapter, stats: Counter) -> list[dict]:
    """The original distillation, re-emitted with current prompts (call chain included)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "proofhound_build_dataset", Path("training/generate/build_dataset.py")
    )
    bd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bd)

    attempts: dict[tuple[str, str], list[dict]] = {}
    for r in bd._jsonl(sorted(DATA.glob("distill_attempts_*.jsonl"))):
        attempts.setdefault((r["case"], r["finding_id"]), []).append(r)

    rows: list[dict] = []
    for p in bd._jsonl(sorted(DATA.glob("distill_progress_*.jsonl"))):
        if not p.get("confirmed"):
            continue
        run = bd.last_run(attempts.get((p["case"], p["finding"]), []))
        index = next((i for i, r in enumerate(run) if r["reached"]), None)
        if index is None:
            stats["A skip: no reached attempt"] += 1
            continue
        winner = run[index]
        if winner["split"] == "eval":
            stats["A skip: eval split"] += 1
            continue
        parsed = bd.finding_from_v1(winner["prompt"].split(bd.OLD_REPAIR)[0], winner["finding_id"])
        if parsed is None:
            stats["A skip: prompt not parsed"] += 1
            continue
        finding, _ = parsed
        if bd.confirmed_kind(adapter, p["case"], finding) is None:
            stats["A skip: detector does not match class"] += 1
            continue
        repo = TRAIN_CASES / p["case"] / "repo"
        if not repo.is_dir():
            stats["A skip: repo missing"] += 1
            continue
        prompt = make_prompt(finding, repo, adapter)
        if prompt is None:
            stats["A skip: prompt build failed"] += 1
            continue
        rows.append({
            "prompt": prompt, "completion": strip_fence(winner["output"]),
            "source": "distillation-v1", "prompt_version": PROMPT_VERSION,
            "case": p["case"], "finding_id": finding.id, "vuln_class": finding.vuln_class,
            "split": case_split(p["case"]),
        })
        stats["A kept"] += 1
    return rows


def source_b(adapter: JavaScriptAdapter, eval_prompts: dict, stats: Counter,
             verified: list[tuple[str, str]]) -> list[dict]:
    """Claude + Gemini trajectories, re-prompted in the pipeline's format."""
    from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
    from proofhound.core.analysis.semgrep import SemgrepEngine

    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), Path("rules/semgrep/javascript"))
    findings_cache: dict[str, dict[str, Finding]] = {}

    rows: list[dict] = []
    for path in sorted((DATA / "distill-v5").glob("*.json")):
        d = json.loads(path.read_text(encoding="utf-8"))
        if d.get("attempts_before_success") is None:
            stats["B skip: partial trajectory"] += 1
            continue
        case, fid = d["case"], d["finding_id"]
        harness = strip_fence(d.get("final_harness", ""))
        if not harness:
            stats["B skip: no harness"] += 1
            continue

        case_dir = next(
            (root / case for root in (TRAIN_CASES, BENCH_CASES) if (root / case / "repo").is_dir()),
            BENCH_CASES / case,
        )
        repo = case_dir / "repo"
        if not repo.is_dir():
            stats["B skip: repo missing"] += 1
            continue

        if case not in findings_cache:
            try:
                manifest = yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))
                analysis = analyzer.run(AnalyzeJob(repo, manifest["commit"]))
                findings_cache[case] = {f.id: f for f in analysis.findings}
            except Exception as e:
                stats[f"B skip: analyzer failed ({type(e).__name__})"] += 1
                findings_cache[case] = {}
        finding = findings_cache[case].get(fid)
        if finding is None:
            # Gemini numbered findings with its own ids. The sink location in the trajectory
            # still pins the finding exactly, so match on "<file>:<line>" plus the class.
            finding = match_by_sink(findings_cache[case], d.get("sink"), d.get("vuln_class"))
            if finding is None:
                stats["B skip: finding not found by id or sink"] += 1
                continue
            stats["B matched by sink instead of id"] += 1
            fid = finding.id

        prompt = make_prompt(finding, repo, adapter)
        if prompt is None:
            stats["B skip: prompt build failed"] += 1
            continue

        for log_name, real in eval_prompts.get((case, fid), []):
            if real.strip() == prompt.strip():
                verified.append((case, fid, log_name))
            else:
                stats[f"prompt differs from {log_name} (written by older code)"] += 1

        rows.append({
            "prompt": prompt, "completion": harness,
            "source": "distillation-v5", "prompt_version": PROMPT_VERSION,
            "case": case, "finding_id": fid, "vuln_class": d.get("vuln_class"),
            "split": case_split(case),
        })
        stats["B kept"] += 1
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DATA / "harness_train_v6.jsonl")
    ap.add_argument("--max-prompt-tokens", type=int, default=8192,
                    help="Drop examples whose prompt exceeds this. The trainer shrinks long "
                         "prompts to fit its window; past this point so little of the module "
                         "source survives that the example stops resembling a real one.")
    args = ap.parse_args()

    adapter = JavaScriptAdapter()
    stats: Counter = Counter()
    verified: list[tuple[str, str, str]] = []
    eval_prompts = load_eval_prompts()
    print(f"findings with a saved real prompt to verify against: {len(eval_prompts)}\n")

    rows = source_a(adapter, stats) + source_b(adapter, eval_prompts, stats, verified)

    if eval_prompts and not verified:
        sys.exit(
            "aborting: not one rebuilt prompt matched a saved eval log, so the training prompts\n"
            "are not what the pipeline sends. Fix make_prompt() before training on this data."
        )

    unique: dict[tuple[str, str], dict] = {}
    for r in rows:
        key = (r["prompt"], r["completion"])
        if key in unique:
            stats["duplicates dropped"] += 1
            continue
        unique[key] = r
    rows = list(unique.values())

    before = len(rows)
    rows = [r for r in rows if r.get("split") == "train"]
    stats["dropped non-train rows (leak guard)"] += before - len(rows)

    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-14B-Instruct")
    sized, oversized = [], []
    for r in rows:
        n = len(tok(r["prompt"]).input_ids)
        (oversized if n > args.max_prompt_tokens else sized).append((n, r))
    for n, r in sorted(oversized, key=lambda x: -x[0]):
        stats[f"dropped oversized prompt ({n} tok): {r['case']}"] += 1
    rows = [r for _, r in sized]

    assert all(r.get("split") == "train" for r in rows), "non-train row reached output"

    args.out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                        encoding="utf-8")

    for key in sorted(stats):
        print(f"  {key}: {stats[key]}")
    by_log = Counter(log for _, _, log in verified)
    print(f"\n  prompts verified byte-for-byte against a real pipeline prompt: {len(verified)}")
    for log, n in sorted(by_log.items()):
        print(f"    via {log}: {n}")
    print(f"  by class: {dict(Counter(r['vuln_class'] for r in rows))}")
    print(f"  by source: {dict(Counter(r['source'] for r in rows))}")
    print(f"\n-> {args.out}: {len(rows)} examples")
    if not rows:
        sys.exit(1)


if __name__ == "__main__":
    main()
