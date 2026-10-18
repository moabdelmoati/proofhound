# ProofHound — Base-Model Selection (Term 1, T1-A deliverable)

Choosing the open code base model our small agents (Harness, Patcher, Triage, Analyzer filter) are
fine-tuned from with QLoRA on Google Colab. The cascade uses **one** base model shared by all
agents, each with its own LoRA adapter, to keep training cheap.

## Requirements

- **Open weights**, permissive license (we redistribute adapters).
- **1.5B–7B** parameters — must QLoRA-fine-tune and run inference on a **free/Pro Colab GPU**
  (T4 16 GB, sometimes L4/A100).
- Strong at **code**, especially JavaScript/TypeScript.
- Good **fill-in-the-middle / instruction** behaviour for harness and patch generation.

## Candidates

| Model | Sizes | License | Notes |
|---|---|---|---|
| **Qwen2.5-Coder** | 0.5 / 1.5 / 3 / 7 / 14 / 32B | Apache-2.0 (coder line) | Leads open coding benchmarks in its size tiers; 7B reported to fit ~8 GB VRAM; strong HumanEval (7B-Instruct ≈ 87). **Primary candidate.** |
| DeepSeek-Coder (V1 6.7B; V2-Lite) | 1.3 / 6.7B; V2-Lite 16B-MoE | permissive | V2 is 236B MoE — out of range; V2-Lite (~16B MoE) is heavier than our budget. V1 6.7B is a fallback. |
| StarCoder2 | 3 / 7 / 15B | BigCode OpenRAIL-M | Trained on The Stack v2 (which we also use for data); little recent head-to-head benchmark data at these sizes. Secondary. |
| CodeLlama | 7 / 13 / 34B | Llama community | Older; generally behind Qwen2.5-Coder on code. Baseline only. |

## Recommendation

- **Primary: `Qwen2.5-Coder-7B-Instruct`** for the main runs — best code quality in range, Apache-2.0,
  fits a Colab GPU under 4-bit QLoRA.
- **Pilot/dev: `Qwen2.5-Coder-1.5B` or `-3B`** — faster QLoRA iterations for the Term 1 pilot and
  for the cheap end of the cascade; report where the small model is enough vs. where escalation to
  the large model is needed (RQ6).
- **Confirm the exact checkpoint's license** before redistributing adapters (the coder line is
  Apache-2.0; the general Qwen2.5 base has a custom license).

## QLoRA settings (starting point, to tune)

- 4-bit NF4 quantization, double quant, fp16 compute (bitsandbytes).
- LoRA rank 16–32 (rank 32 a common sweet spot; rank 8 can underfit), `alpha = 2×rank`, dropout
  0.05, `target_modules = all-linear`.
- 3 epochs, batch size 1 with gradient accumulation 8, lr 2e-4, max length 4096.
- These match `training/train/colab_train_harness.ipynb`; set `MODEL` there to the chosen
  checkpoint.

## Caveat

The public comparisons are mostly SEO blogs and a single technical-report table; numbers vary by
version. **Before committing,** run a quick head-to-head of Qwen2.5-Coder-1.5B/3B/7B on our own
held-out harness-generation task (the verified attempts the pipeline logs) and pick by measured
first-attempt success, not by blog benchmarks.
