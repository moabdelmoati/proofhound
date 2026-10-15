"""Local QLoRA fine-tune of a small code model for the Harness agent (Term 1 pilot).

Designed for a 6 GB laptop GPU: 4-bit QLoRA on a small Qwen2.5-Coder checkpoint. Training data =
OSS-Fuzz seed harnesses (shape) + the pipeline's verified distillation attempts (targeting),
excluding anything tagged split="eval" (no benchmark leakage).

    python training/train_local.py --model Qwen/Qwen2.5-Coder-0.5B --epochs 3

Produces a LoRA adapter under models/harness-adapter/. Serve it by merging into the base and
importing into Ollama, or load base+adapter with transformers for evaluation.
"""

import argparse
import json
from pathlib import Path


def load_examples() -> list[dict]:
    rows: list[dict] = []
    seed = Path("training/data/seed_ossfuzz.jsonl")
    if seed.exists():
        for line in seed.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                rows.append({"prompt": r["prompt"], "completion": r["completion"]})
    attempts = Path("training/data/harness_attempts.jsonl")
    if attempts.exists():
        for line in attempts.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            # Verified distillation only: the harness reached its target, and never from eval cases.
            if r.get("reached") and r.get("split") != "eval" and r.get("output"):
                rows.append({"prompt": r["prompt"], "completion": r["output"]})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-0.5B")
    ap.add_argument("--out", default="models/harness-adapter")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-length", type=int, default=2048)
    ap.add_argument("--lora-rank", type=int, default=16)
    args = ap.parse_args()

    examples = load_examples()
    print(f"training examples: {len(examples)} "
          f"(seed + verified distillation, eval excluded)")
    if len(examples) < 8:
        print("WARNING: very few examples; this pilot only demonstrates the training loop.")

    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def to_text(ex: dict) -> dict:
        # Simple instruction format; the harness prompt already carries the full instruction.
        return {"text": ex["prompt"] + "\n\n" + ex["completion"] + tokenizer.eos_token}

    ds = Dataset.from_list(examples).map(to_text)

    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model, quantization_config=bnb, device_map="auto", torch_dtype=torch.float16,
    )
    lora = LoraConfig(
        r=args.lora_rank, lora_alpha=args.lora_rank * 2, lora_dropout=0.05,
        task_type="CAUSAL_LM", target_modules="all-linear",
    )
    cfg = SFTConfig(
        output_dir=args.out, num_train_epochs=args.epochs, per_device_train_batch_size=1,
        gradient_accumulation_steps=8, learning_rate=2e-4, logging_steps=2,
        save_strategy="epoch", max_length=args.max_length, fp16=True, report_to=[],
        dataset_text_field="text", gradient_checkpointing=True, optim="paged_adamw_8bit",
    )
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds, peft_config=lora)
    trainer.train()
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"saved LoRA adapter -> {args.out}")


if __name__ == "__main__":
    main()
