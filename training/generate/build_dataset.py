"""Build the harness training set from the distillation logs, in the pipeline's current prompt format.

    python training/generate/build_dataset.py            # -> training/data/harness_train.jsonl

Keeps only harnesses that *proved* their finding: the fuzzer confirmed a crash and the bug detector
that fired matches the finding's vulnerability class. A harness that merely reached its target
function may still never execute the sink, so it is not a lesson worth learning.

The logs were written by an older prompt version, so every prompt is rebuilt with the current
`build_prompt` / `repair_prompt`: the sink line is recovered from the finding id (a hash of rule,
path, line and column) and marked, and a repair example shows the previous harness, as the
pipeline now does. A repair whose previous reply held no harness (an empty reply) becomes a
first-attempt example, since that reply taught the model nothing.

Needs training/cases/<case>/out/<finding>/fuzz.log from the distillation run; no LLM, no Docker.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.harness.agent import (
    PROMPT_VERSION,
    build_prompt,
    repair_prompt,
    reply_problem,
)
from proofhound.core.harness.check import summarize_failure
from proofhound.core.llm.client import Completion
from proofhound.core.models import ChangedFunction, Finding, Severity, kind_matches_class

DATA = Path("training/data")
CASES = Path("training/cases")
OLD_REPAIR = "\n\nThe previous harness failed this execution check."

# The v1 generation prompt, which the logs hold; parsed back into its parts.
_V1 = re.compile(
    r"Generate a harness that invokes this changed function with fuzz-derived data\.\n"
    r"Module path inside the sandbox: (?P<module>.+)\n"
    r"Function name: (?P<name>.+)\n"
    r"Function source \(line (?P<start>\d+) onward\):\n```javascript\n(?P<function>.*?)\n```\n"
    r"\nFinding: (?P<rule>\S+) \((?P<severity>\w+)\)\n"
    r"Vulnerability class: (?P<vuln_class>.+)\n"
    r"Source: (?P<source>.*)\nSink: (?P<sink>.*)\n"
    r"Finding message: (?P<message>.*)\n"
    r"Full module source, for understanding imports and exports:\n```javascript\n(?P<module_source>.*)\n```\n"
    r"Harness template to complete:\n```javascript\n(?P<template>.*)\n```\Z",
    re.DOTALL,
)


def _jsonl(paths: list[Path]) -> list[dict]:
    return [json.loads(line) for p in paths for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def sink_position(finding_id: str, rule: str, path: str, start: int, end: int) -> tuple[int, int] | None:
    """Invert the finding id (sha1 of rule|path|line|col) over the function's lines."""
    for line in range(start, end + 1):
        for col in range(1, 400):
            if hashlib.sha1(f"{rule}|{path}|{line}|{col}".encode()).hexdigest()[:10] == finding_id:
                return line, col
    return None


def finding_from_v1(prompt: str, finding_id: str) -> tuple[Finding, dict] | None:
    m = _V1.match(prompt)
    if not m:
        return None
    module = m["module"]
    path = module.removeprefix("/work/target/")
    start = int(m["start"])
    end = start + m["function"].count("\n")
    position = sink_position(finding_id, m["rule"], path, start, end)
    if position is None:
        return None
    unknown = lambda v: None if v == "unknown" else v  # noqa: E731
    function = ChangedFunction(file=Path(path), name=m["name"], start_line=start, end_line=end,
                               language="javascript")
    finding = Finding(
        id=finding_id, rule_id=m["rule"], severity=Severity(m["severity"]), message=m["message"],
        file=Path(path), line=position[0], source=unknown(m["source"]), sink=unknown(m["sink"]),
        vuln_class=unknown(m["vuln_class"]), function=function,
    )
    return finding, m.groupdict()


def confirmed_kind(adapter: JavaScriptAdapter, case: str, finding: Finding) -> str | None:
    """The bug detector that fired in the distillation fuzz run, if it matches the finding."""
    log = CASES / case / "out" / finding.id / "fuzz.log"
    if not log.is_file():
        return None
    if not finding.vuln_class:
        return None
    for report in adapter.parse_reports(log.read_text(encoding="utf-8", errors="replace")):
        if report.is_vulnerability and kind_matches_class(report.kind, finding.vuln_class):
            return report.kind
    return None


def last_run(records: list[dict]) -> list[dict]:
    """The attempts of the last produce() call (attempt numbers restart at 1 on a rerun)."""
    runs: list[list[dict]] = []
    for r in records:
        if r["attempt"] == 1 or not runs:
            runs.append([])
        runs[-1].append(r)
    return runs[-1]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--progress", type=Path, nargs="*", default=sorted(DATA.glob("distill_progress_*.jsonl")))
    ap.add_argument("--attempts", type=Path, nargs="*", default=sorted(DATA.glob("distill_attempts_*.jsonl")))
    ap.add_argument("--out", type=Path, default=DATA / "harness_train.jsonl")
    args = ap.parse_args()

    adapter = JavaScriptAdapter()
    attempts: dict[tuple[str, str], list[dict]] = {}
    for r in _jsonl(args.attempts):
        attempts.setdefault((r["case"], r["finding_id"]), []).append(r)

    stats: Counter = Counter()
    rows: list[dict] = []
    for p in _jsonl(args.progress):
        if not p.get("confirmed"):
            continue
        stats["confirmed"] += 1
        run = last_run(attempts.get((p["case"], p["finding"]), []))
        index = next((i for i, r in enumerate(run) if r["reached"]), None)
        if index is None:
            stats["skip: no reached attempt in log"] += 1
            continue
        winner = run[index]
        if winner["split"] == "eval":
            stats["skip: eval split"] += 1
            continue
        parsed = finding_from_v1(winner["prompt"].split(OLD_REPAIR)[0], winner["finding_id"])
        if parsed is None:
            stats["skip: prompt not parsed / sink line not recovered"] += 1
            continue
        finding, parts = parsed
        kind = confirmed_kind(adapter, p["case"], finding)
        if kind is None:
            stats["skip: bug detector does not match the finding's class"] += 1
            continue

        prompt = build_prompt(finding, parts["function"], parts["module_source"], parts["module"],
                              parts["template"])
        previous = run[index - 1] if index > 0 else None
        if previous and previous["output"].strip() != winner["output"].strip() and not reply_problem(
            Completion(previous["output"], 0, 0, "", "stop"), previous["output"]
        ):
            failure = winner["prompt"].split("\nFailure: ", 1)[1]
            stage, _, error = failure.partition(": ")
            prompt = repair_prompt(prompt, previous["output"], f"{stage}: {summarize_failure(error)}")
            stats["repair examples"] += 1
        elif index > 0:
            stats["repair -> first attempt (previous reply held no harness)"] += 1

        rows.append({
            "prompt": prompt, "completion": winner["output"], "source": "distillation",
            "prompt_version": PROMPT_VERSION, "case": p["case"], "finding_id": finding.id,
            "vuln_class": finding.vuln_class, "bug": kind, "attempt": winner["attempt"],
        })

    args.out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    for key, n in stats.items():
        print(f"  {key}: {n}")
    print(f"  by class: {dict(Counter(r['vuln_class'] for r in rows))}")
    print(f"-> {args.out}: {len(rows)} examples")
    if not rows:
        sys.exit(1)


if __name__ == "__main__":
    main()
