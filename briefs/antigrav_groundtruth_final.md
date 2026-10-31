# Antigravity — Final ground-truth evaluation on all 31 benchmark cases

This produces the headline number for the thesis. Every earlier eval scored the model against the
full SAST finding set, which over-approximates (it flags `.split()` calls and linear regexes as
redos, etc.). The benchmark actually ships one authoritative vulnerability per case
(`case.yaml: ground_truth`). A new mode, `--ground-truth-only` (already committed, commit f526704),
evaluates only that finding. The 31 ground-truth vulnerabilities are **27 command-injection + 4
path-traversal — zero redos, zero prototype-pollution** — the two classes the v8 model handles at
~100% on the 4-case sample (verified 4/4 confirmed).

Goal: run `compare.py --ground-truth-only` on all 31 benchmark cases with the v8 adapter, get the
final confirmed rate, then DESTROY the cloud box.

## Critical: do not leave the box running

A previous session lost ~$4 by leaving an instance up after it finished. Credit is ~$5.5. So:
- Put the destroy step in a `finally` / run it no matter what the eval returns.
- After destroying, verify with `vast_ctl.py show` (or the vast CLI) that no instance is left.
- Confirm `nvidia-smi`-equivalent idle before paying more: do not rent a second box while one runs.

## Architecture (reuse what worked in the v6 cloud runs — see runs/cloud15-14b-v6)

Docker-in-Docker does NOT work on the vast.ai box (unprivileged container). So the box only serves
the model; fuzzing stays local:
- Cloud GPU runs `serve_local.py --load-4bit` on port 8000.
- `compare.py` runs LOCALLY, fuzzing in local Docker, reaching the cloud model over an SSH tunnel
  (`ssh -L 8000:127.0.0.1:8000 ...`). `local-harness` in configs/default.yaml already points at
  127.0.0.1:8000, so no config change.
- Control script: `scripts/vast_ctl.py` (offer/rent/show/ssh/destroy). If `vastai` is not installed
  in `.venv`, `pip install vastai` first. The money-gate permission rule is in
  `.claude/settings.local.json`.

Gotchas from memory to apply:
- Drop `extra_special_tokens` from the adapter's `tokenizer_config.json` before serving (transformers
  rejects it as a list). The v8 adapter is at `models/harness-adapter-14b-v8/`.
- Serving deps on the box: `transformers peft bitsandbytes accelerate pydantic protobuf sentencepiece
  tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-python`.
- Avoid China hosts (HuggingFace unreachable). Pick a verified RTX 3090/4090, ~24GB, ~$0.2-0.3/hr.
- The base model `Qwen/Qwen2.5-Coder-14B-Instruct` is ~28GB; downloads on the box, quantized at load.

## Steps

1. Rent a box (`vast_ctl.py rent ...` or the UI), SSH in, install serving deps, upload the v8
   adapter (or `kaggle kernels output` it on the box), start `serve_local.py --adapter
   <v8 adapter> --base unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit --load-4bit --port 8000`.
2. Open the SSH tunnel locally: `ssh -L 8000:127.0.0.1:8000 <box> -N &`. Confirm
   `curl http://127.0.0.1:8000/v1/models` returns the model.
3. Run locally (Docker must be up):
   ```
   .venv/Scripts/python.exe -m proofhound.evaluation.compare \
       --models local-harness --cases benchmark/cases \
       --out runs/groundtruth-final-v8 \
       --ground-truth-only \
       --class-seeds --rejection-sampling --call-chain-v2 \
       --progress-every 1
   ```
   This evaluates exactly one finding per case (31 total). At ~5 tok/s cloud serving and 5 rejection
   attempts, budget ~2-3 hours. If it is running long, 3 attempts is acceptable — set the default
   temps in `produce_with_sampling` to `[0.1, 0.3, 0.7]` (throwaway edit, revert before commit).
4. **Destroy the box** (and kill the tunnel). Verify nothing is left running.

## Report — `runs/groundtruth-final-v8/REPORT.md`

- Overall: confirmed / reached / loaded out of 31, as counts and %.
- By class: command-injection (of 27) and path-traversal (of 4).
- The list of any ground-truth cases NOT confirmed, each with: best stage reached and the one most
  likely reason from the attempt log (harness wrong shape, sandbox/env block like a missing binary,
  genuine miss). Keep it factual, one line each.
- Headline line comparing to the documented references: 7B v4 (3.7% confirmed on its finding set) and
  Claude (~53% on the noisy set / ~100% on ground truth where documented).

Commit `runs/groundtruth-final-v8/` to `distill/v4-cloud`. Do not retrain or change hyperparameters.
Do not touch `benchmark/cases/`. Stop after the box is destroyed and the report is committed.
