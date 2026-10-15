"""Build a seed dataset of real Jazzer.js harnesses from OSS-Fuzz JavaScript projects.

These teach the model the *shape* of a correct Jazzer.js harness (FuzzedDataProvider usage,
module.exports.fuzz, error handling). They are combined with the verified distillation data the
pipeline logs (which teaches *targeting a specific SAST sink*).

Usage:
    # clone OSS-Fuzz projects first (sparse):
    #   git clone --filter=blob:none --no-checkout --depth 1 https://github.com/google/oss-fuzz
    #   cd oss-fuzz && git sparse-checkout set projects && git checkout
    python training/build_seed.py --oss-fuzz vendor/oss-fuzz --out training/data/seed_ossfuzz.jsonl

Output: JSONL with {source, project, file, split, prompt, completion}. OSS-Fuzz harnesses are
Apache-2.0; the license header is stripped from each `completion` and attribution is kept in `file`.
"""

import argparse
import json
from pathlib import Path

PROMPT = (
    "You write minimal, executable Jazzer.js fuzz harnesses for JavaScript/TypeScript.\n"
    "Package: {project}\n"
    "Write a Jazzer.js harness that exports module.exports.fuzz = function(data) and uses the "
    "@jazzer.js/core FuzzedDataProvider to drive the package's API. Output only the harness."
)


def _strip_license(code: str) -> str:
    lines = code.splitlines()
    i = 0
    while i < len(lines) and (
        lines[i].strip().startswith(("//", "/*", "*"))
        or lines[i].strip() == ""
        or lines[i].strip().endswith("*/")
    ):
        i += 1
    return "\n".join(lines[i:]).strip()


def build(oss_fuzz: Path, out: Path) -> int:
    js_projects = [
        p.parent.name
        for p in oss_fuzz.glob("projects/*/project.yaml")
        if "language:javascript"
        in p.read_text(encoding="utf-8", errors="replace").lower().replace(" ", "")
    ]
    rows = []
    for proj in js_projects:
        for f in (oss_fuzz / "projects" / proj).rglob("*.js"):
            body = _strip_license(f.read_text(encoding="utf-8", errors="replace"))
            if "fuzz" not in body.lower():
                continue
            rows.append({
                "source": "ossfuzz", "project": proj,
                "file": f.relative_to(oss_fuzz).as_posix(), "split": "train",
                "prompt": PROMPT.format(project=proj), "completion": body,
            })
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
    )
    return len(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--oss-fuzz", type=Path, default=Path("vendor/oss-fuzz"))
    ap.add_argument("--out", type=Path, default=Path("training/data/seed_ossfuzz.jsonl"))
    args = ap.parse_args()
    n = build(args.oss_fuzz, args.out)
    print(f"wrote {n} seed harnesses -> {args.out}")
