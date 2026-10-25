# Antigravity Task — Local 14B v5 Smoke Test (ONE case)

**Goal:** Verify whether the newly-trained 14B v5 adapter can run inference on this machine's local GPU (RTX 4050, 6 GB VRAM) at all, and if yes, measure how long one harness generation takes. We need this before committing to a full 35-case eval.

**Context:**
- `models/harness-adapter-14b-v5/` is the LoRA adapter trained on 20 distilled trajectories.
- Base model: `unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit` (4-bit, ~7 GB on disk).
- Phase 3 features live on branch `phase3-features` (seeds + rejection sampling + call-chain v2).
- Current branch is `distill/v4-cloud` with Phase 1 + 2 artifacts.

**Prompt-version note:** The training log warned that the 20 training examples use `prompt_version: harness-v4` while `src/proofhound/core/harness/agent.py` still exports `PROMPT_VERSION = "harness-v3"`. First thing: grep for `PROMPT_VERSION` across `src/`, verify what version the live pipeline builds, and if there's a mismatch, fix `PROMPT_VERSION` to `"harness-v4"` so inference uses the same prompt shape the model was trained on. Commit that fix as its own commit.

---

## Steps

### 1. Prompt-version check (first, before anything else)
- Grep `PROMPT_VERSION` across `src/proofhound/`.
- The dataset was built with `harness-v4` (see `training/data/distill-v5-promptcompletion.jsonl` — first line's `prompt_version`).
- If `PROMPT_VERSION` != `"harness-v4"` in `src/proofhound/core/harness/agent.py`, change it to `"harness-v4"`. Also check `src/proofhound/evaluation/compare.py` references.
- Commit the fix.

### 2. Merge `phase3-features` into current branch
- `git merge origin/phase3-features` on branch `distill/v4-cloud`.
- Resolve any conflicts (likely in `agent.py`, `compare.py`, `call_chain.py`).
- Verify imports still work: `.venv/Scripts/python.exe -c "from proofhound.evaluation.compare import main"`.

### 3. Start the local inference server with the 14B adapter
- Pick an easy test case to confirm end-to-end: `aaptjs_1.3.1` (small, cmd-injection, we already have a Claude trajectory for it to compare against).
- Launch `training/serve/serve_local.py`:
  ```
  .venv/Scripts/python.exe training/serve/serve_local.py \
      --adapter models/harness-adapter-14b-v5 \
      --base unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit \
      --device cuda \
      --load-4bit \
      --port 8000
  ```
- Pipe stdout/stderr to `.trash_cleanup/serve-14b.log` so it does not clog the shell.
- Wait up to 10 minutes for the "model ready" line. If it OOMs during load, that's the answer — stop here and report.
- If it loads, note the "prompt budget" line and VRAM usage (`nvidia-smi` in a side terminal).

### 4. Run compare.py on ONE case with ALL Phase 3 features enabled
```
.venv/Scripts/python.exe -m proofhound.evaluation.compare \
    --models local-harness \
    --cases benchmark/cases \
    --max-cases 1 \
    --out runs/smoke-14b-v5 \
    --class-seeds \
    --rejection-sampling \
    --call-chain-v2
```
- Record wall-clock time for the single finding.
- Note: `--max-cases 1` picks the first case alphabetically (`aaptjs_1.3.1`).

### 5. Stop the server when done
- `taskkill /F /PID <pid>` or whatever the serve script's PID is.

---

## What to report back

Save a short Markdown summary to `runs/smoke-14b-v5/REPORT.md` with:

- **Load success?** (Y/N)
- **VRAM used at load** (GB)
- **Tokens/second during generation** (from the server's log lines like `prompt N -> M tokens in Ts (X tok/s)`)
- **Wall-clock for the one finding** (seconds / minutes)
- **How many of its 5 rejection-sampling attempts actually ran** (vs OOM / timeout mid-run)
- **Confirmed? Reached? Loaded?** (from the attempts jsonl)
- **Projected time for the full 35-case eval** if we extrapolate linearly
- **Projected feasibility** — your judgement: can we run the full eval on this GPU, or do we need Kaggle / cloud / smaller model?

That is enough — we are not trying to get a confirmed harness here, we are measuring whether the hardware can run this at all.

---

## Stop conditions

- Hard stop on OOM at model load → report "won't fit, need to switch to CPU offload or external GPU"
- Hard stop if one attempt takes > 20 minutes → report "too slow for full eval"
- Hard stop after 90 minutes real time regardless of state → report what did/didn't work

Do NOT try to fix OOM by changing bitsandbytes config or quantizing further — that's a design decision we need to make together, not a workaround.
