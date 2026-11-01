"""Analyze failures from a ProofHound compare run.

Reads attempts JSONL + per-finding probe/fuzz logs, classifies each finding's best
outcome, and emits:
  - failure_analysis.md : human-readable per-class breakdown with recommendations
  - failure_analysis.csv: one row per finding for spreadsheet analysis
  - target_findings.jsonl: the subset to prioritize for Claude distillation
"""
import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path


# Signatures that mark environment issues (not model failures)
ENV_SIGNATURES = [
    (re.compile(r"PlistBuddy", re.I),         "macOS-only binary (PlistBuddy)"),
    (re.compile(r"Cannot find module", re.I), "missing node module"),
    (re.compile(r"ENOENT.+/usr/local/bin"),   "missing linux binary"),
    (re.compile(r"spawn .+ ENOENT"),          "spawn ENOENT (missing exe)"),
    (re.compile(r"xcrun|xcode", re.I),        "macOS-only toolchain"),
    (re.compile(r"EACCES"),                   "permission denied in sandbox"),
    (re.compile(r"out of memory|OOM", re.I),  "out of memory"),
]


def classify_env_block(finding_dir: Path) -> str | None:
    """Return env-block reason if any log in this finding matches a known signature."""
    for log_name in ("harness-probe.log", "fuzz.log", "coverage.log"):
        for attempt_dir in finding_dir.rglob(log_name):
            try:
                text = attempt_dir.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for sig, label in ENV_SIGNATURES:
                if sig.search(text):
                    return label
    return None


def classify_finding(best: dict, finding_dir: Path | None) -> tuple[str, str]:
    """Return (category, detail). Categories:
      confirmed, reached_not_confirmed, loaded_not_reached,
      syntax_ok_not_loaded, env_blocked, syntax_fail, no_output.
    """
    if best.get("crash_confirmed"):
        return "confirmed", "crash reproduced"
    if best.get("reached"):
        return "reached_not_confirmed", "harness reached sink but no crash from fuzzer"

    # Reached-fail: harness loaded in Docker but did not reach sink.
    if best.get("loaded"):
        env = classify_env_block(finding_dir) if finding_dir and finding_dir.exists() else None
        if env:
            return "env_blocked", env
        return "loaded_not_reached", "fuzzer did not hit the sink line"

    if best.get("syntax_ok"):
        return "syntax_ok_not_loaded", f"load error at stage={best.get('failed_stage','?')}"

    stage = best.get("failed_stage") or "?"
    if stage in ("no_harness", "?"):
        return "no_output", f"model produced no harness (stage={stage})"
    return "syntax_fail", f"syntax or parse error (stage={stage})"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default="runs/compare-v4-full", type=Path)
    ap.add_argument("--model",   default="local-harness")
    args = ap.parse_args()

    run_dir = args.run_dir.resolve()
    jsonl   = run_dir / f"attempts_{args.model}.jsonl"
    if not jsonl.exists():
        raise SystemExit(f"attempts jsonl not found: {jsonl}")

    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"Loaded {len(rows)} attempts from {jsonl.name}")

    # Best stage per finding
    best = defaultdict(lambda: {
        "syntax_ok": False, "loaded": False, "reached": False, "crash_confirmed": False,
        "failed_stage": None, "attempts": 0,
    })
    meta = {}
    for r in rows:
        fid = (r["case"], r["finding_id"])
        meta[fid] = {"case": r["case"], "finding_id": r["finding_id"],
                     "vuln_class": r.get("vuln_class", "?"), "split": r.get("split", "?")}
        b = best[fid]
        b["attempts"] += 1
        for s in ("syntax_ok", "loaded", "reached", "crash_confirmed"):
            b[s] = b[s] or bool(r.get(s))
        # Keep the deepest failed_stage seen
        stage = r.get("failed_stage")
        if stage and not b.get("failed_stage"):
            b["failed_stage"] = stage

    findings = []
    for fid, b in best.items():
        m = meta[fid]
        finding_dir = run_dir / m["case"] / m["finding_id"]
        category, detail = classify_finding(b, finding_dir)
        findings.append({**m, **b, "category": category, "detail": detail})

    # Aggregates
    total = len(findings)
    cat_counts   = defaultdict(int)
    class_counts = defaultdict(lambda: defaultdict(int))
    env_reasons  = defaultdict(int)

    for f in findings:
        cat_counts[f["category"]] += 1
        class_counts[f["vuln_class"]][f["category"]] += 1
        if f["category"] == "env_blocked":
            env_reasons[f["detail"]] += 1

    # ── Write CSV ──
    csv_path = run_dir / "failure_analysis.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "case", "finding_id", "vuln_class", "attempts",
            "syntax_ok", "loaded", "reached", "crash_confirmed",
            "failed_stage", "category", "detail",
        ])
        w.writeheader()
        for row in sorted(findings, key=lambda x: (x["vuln_class"], x["case"])):
            w.writerow({k: row[k] for k in w.fieldnames})
    print(f"CSV: {csv_path}")

    # ── Write target findings (priorities for Claude distillation) ──
    #    Priority 1: loaded_not_reached in prototype-pollution/cmd-injection/path-traversal
    #                (highest reach ceiling, worth Claude's reasoning)
    #    Priority 2: reached_not_confirmed in same classes (seed/confirm problem)
    #    Priority 3: env_blocked (document, skip from distillation)
    targets = []
    for f in findings:
        if f["category"] == "confirmed":
            continue  # already works, no need to distill
        if f["category"] == "env_blocked":
            continue  # environment problem, Claude won't help
        pri = 1 if f["category"] == "loaded_not_reached" else (
              2 if f["category"] == "reached_not_confirmed" else 3)
        targets.append({**f, "priority": pri})
    targets.sort(key=lambda x: (x["priority"], x["vuln_class"], x["case"]))

    tgt_path = run_dir / "target_findings.jsonl"
    with tgt_path.open("w", encoding="utf-8") as f:
        for row in targets:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Targets: {tgt_path} ({len(targets)} findings for Claude distillation)")

    # ── Write Markdown report ──
    md_path = run_dir / "failure_analysis.md"
    with md_path.open("w", encoding="utf-8") as f:
        f.write(f"# Failure Analysis — {run_dir.name} ({args.model})\n\n")
        f.write(f"**Total findings:** {total}  |  "
                f"**Cases:** {len({x['case'] for x in findings})}  |  "
                f"**Attempts:** {len(rows)}\n\n")

        f.write("## Category Breakdown\n\n")
        f.write("| Category | Count | % | Meaning |\n")
        f.write("|---|---|---|---|\n")
        legend = {
            "confirmed":              "crash reproduced — the model succeeded",
            "reached_not_confirmed":  "sink reached but fuzzer could not crash it",
            "loaded_not_reached":     "harness loads but can't drive execution to sink",
            "env_blocked":            "sandbox lacks required binary/env",
            "syntax_ok_not_loaded":   "parse-OK code but module/require errors",
            "syntax_fail":            "model emitted invalid code",
            "no_output":              "model produced no usable harness",
        }
        order = ["confirmed", "reached_not_confirmed", "loaded_not_reached",
                 "env_blocked", "syntax_ok_not_loaded", "syntax_fail", "no_output"]
        for cat in order:
            n = cat_counts[cat]
            f.write(f"| {cat} | {n} | {100*n/total:.1f}% | {legend[cat]} |\n")

        f.write("\n## By Vulnerability Class\n\n")
        f.write("| class | total | confirmed | reached_not_conf | loaded_not_reached | env_blocked | other |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for vc in sorted(class_counts):
            cc = class_counts[vc]
            tot = sum(cc.values())
            other = tot - sum(cc[k] for k in ("confirmed","reached_not_confirmed","loaded_not_reached","env_blocked"))
            f.write(f"| {vc} | {tot} | {cc['confirmed']} | {cc['reached_not_confirmed']} "
                    f"| {cc['loaded_not_reached']} | {cc['env_blocked']} | {other} |\n")

        if env_reasons:
            f.write("\n## Environment Block Reasons\n\n")
            for reason, n in sorted(env_reasons.items(), key=lambda x: -x[1]):
                f.write(f"- **{reason}** — {n} findings\n")

        f.write("\n## Distillation Targets (by priority)\n\n")
        f.write(f"Total targets (excluding confirmed + env_blocked): **{len(targets)}**\n\n")
        pri_counts = defaultdict(int)
        for t in targets:
            pri_counts[t["priority"]] += 1
        f.write(f"- **Priority 1** (loaded_not_reached — reach gap): {pri_counts[1]}\n")
        f.write(f"- **Priority 2** (reached_not_confirmed — confirm gap): {pri_counts[2]}\n")
        f.write(f"- **Priority 3** (other): {pri_counts[3]}\n")

        f.write("\n## Confirmed Findings (the baseline wins)\n\n")
        for f_ in findings:
            if f_["category"] == "confirmed":
                f.write(f"- `{f_['case']}` / {f_['vuln_class']} / `{f_['finding_id']}`\n")

        f.write("\n## Recommendations\n\n")
        reach_gap = cat_counts["loaded_not_reached"]
        confirm_gap = cat_counts["reached_not_confirmed"]
        env_lost = cat_counts["env_blocked"]
        f.write(f"1. **Primary bottleneck is reach** — {reach_gap} findings "
                f"({100*reach_gap/total:.0f}%) load but don't reach the sink. "
                "Distillation + call-chain v2 target this directly.\n")
        f.write(f"2. **Confirm gap is {confirm_gap} findings** — these reach the sink but the fuzzer "
                "fails to craft a crashing input. Class-aware seeds target this directly.\n")
        f.write(f"3. **Environment losses: {env_lost} findings** — document and exclude from "
                "distillation target set (fixing them is sandbox work, not model work).\n")

    print(f"Report: {md_path}")

    # ── Console summary ──
    print()
    print(f"{'='*60}")
    print(f"FAILURE ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total findings: {total}")
    for cat in order:
        n = cat_counts[cat]
        bar = "#" * int(30 * n / total)
        print(f"  {cat:<24} {n:>3} ({100*n/total:>4.1f}%)  {bar}")
    print()
    print(f"Distillation targets: {len(targets)} "
          f"(P1={pri_counts[1]}, P2={pri_counts[2]}, P3={pri_counts[3]})")


if __name__ == "__main__":
    main()
