"""QLoRA fine-tune of a small code model for the Harness agent.

Each example is rendered with harness_format (the same chat format serve_local.py uses) and the
loss is computed on the assistant's harness only — never on the prompt — so the model learns to
answer the pipeline's prompt rather than to reproduce it. Over-long prompts are shrunk inside the
source blocks; the harness itself is never truncated (examples that cannot fit are skipped).

Data: training/data/harness_train.jsonl from training/generate/build_dataset.py: distilled
harnesses that proved their finding (crash confirmed by the matching bug detector), with prompts in
the pipeline's current format. Records tagged split="eval" are always excluded.

    # inspect the dataset only (needs just the tokenizer):
    python training/train/train_local.py --dry-run
    # 6 GB laptop GPU:
    python training/train/train_local.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct --max-length 2048
    # Colab (T4 16 GB or better): see training/train/colab_train_harness.ipynb
    python training/train/train_local.py --model Qwen/Qwen2.5-Coder-7B-Instruct --max-length 4096

Needs bitsandbytes (pip install bitsandbytes) for the 4-bit base weights.
"""

import argparse
import json
import random
import statistics
from pathlib import Path

from proofhound.core.harness import chat_format as fmt
from proofhound.core.harness.agent import PROMPT_VERSION

DEFAULT_DATA = Path("training/data/harness_train.jsonl")
MIN_PROMPT_TOKENS = 256


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_examples(paths: list[Path]) -> tuple[list[dict], dict]:
    """{prompt, completion} rows from `paths`, minus eval-split records and exact duplicates."""
    stats = {"eval_excluded": 0, "duplicates": 0, "stale_prompt_version": 0}
    rows: list[dict] = []
    for path in paths:
        for r in _jsonl(path):
            if r.get("split") == "eval":
                stats["eval_excluded"] += 1
                continue
            if r.get("prompt_version") != PROMPT_VERSION:
                stats["stale_prompt_version"] += 1
            source = r.get("source", path.stem)
            stats[source] = stats.get(source, 0) + 1
            rows.append({"prompt": r["prompt"], "completion": r["completion"], "source": source})
    unique: dict[tuple[str, str], dict] = {}
    for r in rows:
        unique.setdefault((r["prompt"], r["completion"]), r)
    stats["duplicates"] = len(rows) - len(unique)
    return list(unique.values()), stats


def tokenize_example(tokenizer, ex: dict, max_length: int, end_id: int) -> dict | None:
    completion_ids = [*tokenizer(ex["completion"].strip(), add_special_tokens=False).input_ids, end_id]
    budget = max_length - len(completion_ids)
    if budget < MIN_PROMPT_TOKENS:
        return None
    prompt = fmt.render_prompt(
        tokenizer, [{"role": "system", "content": fmt.SYSTEM}, {"role": "user", "content": ex["prompt"]}],
        budget,
    )
    prompt_ids = tokenizer(prompt, add_special_tokens=False).input_ids
    return {
        "input_ids": prompt_ids + completion_ids,
        "labels": [-100] * len(prompt_ids) + completion_ids,
        "completion_tokens": len(completion_ids),
    }


def build_dataset(tokenizer, examples: list[dict], max_length: int) -> tuple[list[dict], int]:
    fmt.ensure_chat_template(tokenizer)
    end_id = tokenizer.convert_tokens_to_ids(fmt.END_OF_TURN)
    out, skipped = [], 0
    for ex in examples:
        item = tokenize_example(tokenizer, ex, max_length, end_id)
        if item is None:
            skipped += 1
        else:
            out.append(item)
    return out, skipped


class _Collator:
    def __init__(self, pad_id: int):
        self.pad_id = pad_id

    def __call__(self, batch: list[dict]) -> dict:
        import torch

        width = max(len(b["input_ids"]) for b in batch)
        pad = lambda seq, value: seq + [value] * (width - len(seq))  # noqa: E731
        return {
            "input_ids": torch.tensor([pad(b["input_ids"], self.pad_id) for b in batch]),
            "labels": torch.tensor([pad(b["labels"], -100) for b in batch]),
            "attention_mask": torch.tensor([pad([1] * len(b["input_ids"]), 0) for b in batch]),
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    ap.add_argument("--out", default="models/harness-adapter")
    ap.add_argument("--data", type=Path, nargs="+", default=[DEFAULT_DATA],
                    help="{prompt, completion} JSONL files (training/generate/build_dataset.py).")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-length", type=int, default=2048)
    ap.add_argument("--lora-rank", type=int, default=16)
    ap.add_argument("--target-modules", nargs="+", default=None,
                    help="LoRA target modules (default: all-linear). "
                         "Pass e.g. q_proj k_proj v_proj o_proj to restrict to attention only — "
                         "required to fit a 7B model on a 16 GB T4.")
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--save-steps", type=int, default=50,
                    help="Checkpoint interval; a rerun resumes from the last checkpoint in --out.")
    ap.add_argument("--dry-run", action="store_true", help="Build and inspect the dataset, then stop.")
    args = ap.parse_args()

    from transformers import AutoTokenizer

    examples, stats = load_examples(args.data)
    print(f"examples: {len(examples)}  {stats}")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    data, skipped = build_dataset(tokenizer, examples, args.max_length)
    if not data:
        raise SystemExit("no trainable examples")
    lengths = [len(d["input_ids"]) for d in data]
    completion_lengths = [d["completion_tokens"] for d in data]
    prompt_budget = args.max_length - int(statistics.median(completion_lengths))
    print(f"trainable: {len(data)}  skipped (harness longer than max-length): {skipped}")
    print(f"sequence tokens: median {int(statistics.median(lengths))}  max {max(lengths)}")
    print(f"harness tokens:  median {int(statistics.median(completion_lengths))}  "
          f"max {max(completion_lengths)}  -> serving prompt budget {prompt_budget}")
    if stats["stale_prompt_version"]:
        print(f"WARNING: {stats['stale_prompt_version']} example(s) are not in prompt format "
              f"{PROMPT_VERSION}; the model would be trained on prompts the pipeline no longer "
              "sends. Rebuild them with training/generate/build_dataset.py.")

    if args.dry_run:
        sample = data[0]
        boundary = next(i for i, t in enumerate(sample["labels"]) if t != -100)
        print("=" * 30, "rendered prompt (no loss)", "=" * 30)
        print(tokenizer.decode(sample["input_ids"][:boundary])[-1500:])
        print("=" * 30, "target (loss)", "=" * 30)
        print(tokenizer.decode(sample["input_ids"][boundary:])[:1500])
        return

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig, Trainer, TrainingArguments
    from transformers.trainer_utils import get_last_checkpoint

    random.seed(0)
    random.shuffle(data)
    bf16 = torch.cuda.is_bf16_supported()  # L4/A100; T4 falls back to fp16
    dtype = torch.bfloat16 if bf16 else torch.float16
    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=dtype, bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model, quantization_config=bnb, device_map="auto", torch_dtype=dtype,
    )
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    target_modules = args.target_modules if args.target_modules else "all-linear"
    model = get_peft_model(model, LoraConfig(
        r=args.lora_rank, lora_alpha=args.lora_rank * 2, lora_dropout=0.05,
        task_type="CAUSAL_LM", target_modules=target_modules,
    ))
    model.print_trainable_parameters()

    training_args = TrainingArguments(
        output_dir=args.out, num_train_epochs=args.epochs, per_device_train_batch_size=1,
        gradient_accumulation_steps=args.grad_accum, learning_rate=args.lr,
        lr_scheduler_type="cosine", warmup_steps=10, logging_steps=5,
        save_strategy="steps", save_steps=args.save_steps, save_total_limit=2,
        fp16=not bf16, bf16=bf16, gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False}, optim="paged_adamw_8bit",
        report_to=[], remove_unused_columns=False,
    )
    trainer = Trainer(
        model=model, args=training_args,
        train_dataset=[{k: d[k] for k in ("input_ids", "labels")} for d in data],
        data_collator=_Collator(tokenizer.pad_token_id),
    )
    last = get_last_checkpoint(args.out) if Path(args.out).is_dir() else None
    if last:
        print(f"resuming from {last}")
    trainer.train(resume_from_checkpoint=last)
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    (Path(args.out) / fmt.METADATA_FILE).write_text(json.dumps({
        "base_model": args.model,
        "max_length": args.max_length,
        "prompt_budget": prompt_budget,
        "examples": len(data),
        "data_stats": stats,
    }, indent=2), encoding="utf-8")
    print(f"saved LoRA adapter -> {args.out}")


if __name__ == "__main__":
    main()
