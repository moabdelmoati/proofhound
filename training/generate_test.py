"""Quick proof that the fine-tuned harness model loads and generates a Jazzer.js harness.

    python training/generate_test.py --adapter models/harness-adapter

Loads base + LoRA adapter and generates a harness for a sample package prompt, so we can see the
trained model produce valid harness code locally (no API). Not the full eval — just a smoke test.
"""

import argparse

PROMPT = (
    "You write minimal, executable Jazzer.js fuzz harnesses for JavaScript/TypeScript.\n"
    "Package: command-exists\n"
    "Write a Jazzer.js harness that exports module.exports.fuzz = function(data) and uses the "
    "@jazzer.js/core FuzzedDataProvider to drive the package's API. Output only the harness."
)


def trim_harness(text: str) -> str:
    """Keep one harness: cut repetitions and FIM leakage after module.exports.fuzz closes."""
    # Common special tokens that leak into fine-tuned small models with limited data.
    for marker in ("<|fim_middle|>", "<|fim_prefix|>", "<|fim_suffix|>", "<|endoftext|>"):
        text = text.split(marker, maxsplit=1)[0]
    # Keep only up to the end of the first top-level module.exports.fuzz block.
    marker = "module.exports.fuzz"
    first = text.find(marker)
    if first == -1:
        return text.strip()
    depth = 0
    seen_open = False
    end = len(text)
    for i, ch in enumerate(text[first:], start=first):
        if ch == "{":
            depth += 1
            seen_open = True
        elif ch == "}":
            depth -= 1
            if seen_open and depth == 0:
                end = i + 1
                # include a trailing semicolon if the model emitted one
                if end < len(text) and text[end] == ";":
                    end += 1
                break
    return text[:end].strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="models/harness-adapter")
    ap.add_argument("--base", default=None)
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    ap.add_argument("--max-tokens", type=int, default=300)
    args = ap.parse_args()

    import torch
    from peft import PeftConfig, PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    cfg = PeftConfig.from_pretrained(args.adapter)
    base = args.base or cfg.base_model_name_or_path
    print(f"base: {base}")
    tok = AutoTokenizer.from_pretrained(args.adapter)
    dtype = torch.float16 if args.device == "cuda" else torch.float32
    model = AutoModelForCausalLM.from_pretrained(base, torch_dtype=dtype)
    model = PeftModel.from_pretrained(model, args.adapter).to(args.device).eval()

    msgs = [{"role": "user", "content": PROMPT}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(prompt, return_tensors="pt").to(args.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=args.max_tokens, do_sample=False,
                             pad_token_id=tok.eos_token_id)
    text = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print("=" * 60)
    print(trim_harness(text))
    print("=" * 60)


if __name__ == "__main__":
    main()
