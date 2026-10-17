"""Smoke test: load base + adapter and generate one harness for a real pipeline prompt.

    python training/generate_test.py --adapter models/harness-adapter --device cuda
    python training/generate_test.py --prompts runs/compare-claude/attempts_codecraft-claude.jsonl --index 3

Uses serve_local's loader and generator, so it shows exactly what the server would return.
"""

import argparse
import json
from pathlib import Path

import serve_local


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="models/harness-adapter")
    ap.add_argument("--base", default=None)
    ap.add_argument("--device", default="cuda", choices=["cpu", "cuda"])
    ap.add_argument("--load-4bit", action="store_true")
    ap.add_argument("--prompts", type=Path, default=Path("training/data/harness_attempts.jsonl"),
                    help="JSONL with a `prompt` field (an attempt log or a seed file).")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--max-tokens", type=int, default=1536)
    args = ap.parse_args()

    lines = [line for line in args.prompts.read_text(encoding="utf-8").splitlines() if line.strip()]
    prompt = json.loads(lines[args.index])["prompt"]
    serve_local._load(args.adapter, args.base, args.device, args.load_4bit)
    text, prompt_tokens, completion_tokens, finish = serve_local._generate(
        [{"role": "user", "content": prompt}], args.max_tokens, 0.0
    )
    print(f"prompt {prompt_tokens} tokens -> {completion_tokens} tokens ({finish})")
    print("=" * 60)
    print(text)
    print("=" * 60)


if __name__ == "__main__":
    main()
