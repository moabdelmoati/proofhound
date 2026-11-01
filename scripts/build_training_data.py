"""Convert distilled Claude trajectories into ChatML for 14B QLoRA training.

Reads training/data/distill-v5/*.json (one trajectory per confirmed finding) and
emits training/data/distill-v5-chatml.jsonl (one row per training example).

Each training example has the shape:
  {"messages": [
      {"role": "system",    "content": SYSTEM_PROMPT},
      {"role": "user",      "content": <v4-style harness prompt>},
      {"role": "assistant", "content": <call-chain reasoning + harness>},
  ]}

Partial (unconfirmed) trajectories are skipped unless --include-partial is passed;
they carry weaker signal because the harness never crashed.
"""
import argparse
import json
from pathlib import Path


SYSTEM_PROMPT = (
    "You generate Jazzer.js harnesses that trigger known npm vulnerabilities. "
    "You will be given the vulnerable function, the sink location, and a call "
    "chain from an exported API to the sink. Produce a harness whose single "
    "fuzzed input flows unmodified into the sink's user-controlled argument, "
    "stripping only characters Node refuses outright (NUL bytes). Keep every "
    "pre-sink guard satisfied so execution actually reaches the sink."
)


def build_user_prompt(trajectory: dict) -> str:
    """Reconstruct the v4-style prompt the model would see at inference time."""
    return (
        f"Generate a Jazzer.js harness for this finding.\n"
        f"Case: {trajectory['case']}\n"
        f"Finding ID: {trajectory['finding_id']}\n"
        f"Vulnerability class: {trajectory['vuln_class']}\n"
        f"Sink: {trajectory.get('sink', 'see case.yaml')}\n\n"
        f"The vulnerable function is in the case repo under benchmark/cases/"
        f"{trajectory['case']}/repo/. Read the sink site and the exported APIs "
        f"that reach it. Produce a harness that:\n"
        f"- is a single `module.exports.fuzz = function(data) {{ ... }}`,\n"
        f"- uses FuzzedDataProvider for input shaping,\n"
        f"- satisfies all pre-sink preconditions (type checks, config, OS probes),\n"
        f"- lets the Jazzer.js bug detector for `{trajectory['vuln_class']}` fire."
    )


def build_assistant_response(trajectory: dict) -> str:
    """The full reasoning + harness, as the model should learn to emit it."""
    parts = [
        "## Call chain analysis",
        trajectory["call_chain_analysis"],
        "",
        "## Argument reasoning",
        trajectory["argument_reasoning"],
        "",
        "## Harness",
        "```javascript",
        trajectory["final_harness"].rstrip(),
        "```",
    ]
    return "\n".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir",  default="training/data/distill-v5", type=Path)
    ap.add_argument("--out",     default="training/data/distill-v5-chatml.jsonl", type=Path)
    ap.add_argument("--include-partial", action="store_true",
                    help="Also include trajectories where attempts_before_success is null.")
    args = ap.parse_args()

    in_dir = args.in_dir.resolve()
    jsons = sorted(in_dir.glob("*.json"))
    if not jsons:
        raise SystemExit(f"no trajectories found in {in_dir}")

    kept = 0
    skipped_partial = 0
    examples: list[dict] = []

    for path in jsons:
        try:
            traj = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[skip] {path.name}: parse error ({e})")
            continue

        att = traj.get("attempts_before_success")
        if att is None and not args.include_partial:
            skipped_partial += 1
            continue

        for required in ("case", "finding_id", "vuln_class",
                         "call_chain_analysis", "argument_reasoning", "final_harness"):
            if required not in traj:
                print(f"[skip] {path.name}: missing field '{required}'")
                break
        else:
            examples.append({
                "messages": [
                    {"role": "system",    "content": SYSTEM_PROMPT},
                    {"role": "user",      "content": build_user_prompt(traj)},
                    {"role": "assistant", "content": build_assistant_response(traj)},
                ],
                "meta": {
                    "case": traj["case"],
                    "finding_id": traj["finding_id"],
                    "vuln_class": traj["vuln_class"],
                    "attempts": att,
                },
            })
            kept += 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # Also write train_local.py-compatible format: {prompt, completion, split, prompt_version}
    pc_path = args.out.with_name(args.out.stem.replace("-chatml", "") + "-promptcompletion.jsonl")
    with pc_path.open("w", encoding="utf-8") as f:
        for ex in examples:
            msgs = ex["messages"]
            user = next(m["content"] for m in msgs if m["role"] == "user")
            assistant = next(m["content"] for m in msgs if m["role"] == "assistant")
            f.write(json.dumps({
                "prompt": user,
                "completion": assistant,
                "source": "distill-v5",
                "prompt_version": "harness-v4",
                "split": "train",
                **ex["meta"],
            }, ensure_ascii=False) + "\n")
    print(f"Wrote {kept} prompt/completion rows to {pc_path}")

    print(f"Wrote {kept} training examples to {args.out}")
    if skipped_partial:
        print(f"Skipped {skipped_partial} partial trajectories (pass --include-partial to keep)")

    # Class distribution
    from collections import Counter
    classes = Counter(ex["meta"]["vuln_class"] for ex in examples)
    print(f"\nClass distribution:")
    for cls, n in classes.most_common():
        print(f"  {cls:<25} {n}")


if __name__ == "__main__":
    main()
