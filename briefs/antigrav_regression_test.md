# Antigravity Task — Regression Test (2 cases)

**Goal:** Verify that the 14B v5 adapter does NOT regress on the two cases the 7B v4 baseline already confirms. If 14B v5 fails here, we have a problem to fix BEFORE spending money on cloud eval.

**Context:**
- Previous validation run (`runs/validate-14b-v5-3case/`) showed 14B v5 improves on `arpping_2.0.0` (1 new confirmed + 3 new reached). But ran out of time before testing `asset-cache_0.0.6` and `blamer_0.1.13` — the two baseline-confirmed cases.
- 14B v5 on RTX 4050: ~0.7 tok/s, ~4.5 min per attempt, ~22 min per finding at 5 attempts.
- `rejection_sampling` with 5 attempts proved valuable (rescued redos findings at T=0.3 and T=0.5) but it's the main time cost.

**Trade-off decision:** To fit both cases in a sane time window, cut rejection sampling to **3 attempts** (temperatures `[0.1, 0.3, 0.7]`). We lose the lower-signal T=0.5 and T=0.9 attempts but save ~40% of runtime. Still enough to prove regression one way or the other.

---

## The 2 regression cases

| Case | 7B v4 baseline (must-match) |
| --- | --- |
| `asset-cache_0.0.6` | **2 confirmed** (both path-traversal: `029e512bac`, `a55ef60143`) |
| `blamer_0.1.13` | **1 confirmed** (command-injection: `971e749caf`) |

**Pass criteria (strict):**
- `asset-cache_0.0.6` → 14B v5 must confirm **both** path-traversal findings. Even one missed = regression.
- `blamer_0.1.13` → 14B v5 must confirm the command-injection finding. Missed = regression.

**Soft criteria (bonus):**
- Other findings in either case reaching or confirming (14B v5 could still find new things).

---

## Steps

### 1. Pre-flight (don't skip)
- `netstat -ano | findstr :8000` — kill the previous serve_local.py if still running.
- `nvidia-smi` — confirm VRAM is 0 before starting.
- `git log --oneline -5` — confirm `phase3-features` merge is still in.
- Confirm `models/harness-adapter-14b-v5/adapter_model.safetensors` exists.

### 2. Prepare targeted cases directory
Create `.trash_cleanup/cases_regression/` with just the 2 target cases (symlinks or `xcopy /E /I /Q`):
- `asset-cache_0.0.6`
- `blamer_0.1.13`

### 3. Reduce rejection sampling to 3 attempts
In `src/proofhound/core/harness/agent.py`, find the `produce_with_sampling` method and the default temperatures `[0.1, 0.3, 0.5, 0.7, 0.9]`. For THIS run only, pass `[0.1, 0.3, 0.7]` via the compare.py `--temps` flag if it exists, OR temporarily edit the default to `[0.1, 0.3, 0.7]`.

If editing the default, **do not commit that change** — it is a temporary tweak for this run. Revert before step 7.

### 4. Start the 14B inference server (same as last time)
```
.venv/Scripts/python.exe training/serve/serve_local.py \
    --adapter models/harness-adapter-14b-v5 \
    --base unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit \
    --device cuda --load-4bit --port 8000 \
    > .trash_cleanup/serve-14b.log 2>&1 &
```
Wait for `"model ready"` (should be <2 min — model is cached).

### 5. Run compare.py on the 2 regression cases
```
.venv/Scripts/python.exe -m proofhound.evaluation.compare \
    --models local-harness \
    --cases .trash_cleanup/cases_regression \
    --out runs/regression-14b-v5 \
    --class-seeds \
    --rejection-sampling \
    --call-chain-v2 \
    --progress-every 1
```

### 6. Stop the server and (if you edited it) revert the temperature default
Kill serve_local.py PID. If step 3 required editing the default, revert that edit now so no untracked diff is left.

### 7. Write the report
Save `runs/regression-14b-v5/REPORT.md` with:

- **Regression table** (the main deliverable):
  | Case | Finding | Vuln class | 7B v4 baseline | 14B v5 result | Verdict |
  | --- | --- | --- | --- | --- | --- |
  | `asset-cache_0.0.6` | `029e512bac` | path-traversal | confirmed | ? | PASS / REGRESSION |
  | `asset-cache_0.0.6` | `a55ef60143` | path-traversal | confirmed | ? | PASS / REGRESSION |
  | `blamer_0.1.13` | `971e749caf` | command-injection | confirmed | ? | PASS / REGRESSION |

- **Any bonus findings** (either case may have additional findings beyond the baseline-confirmed ones): list them with their best stage.

- **Final verdict:** PASS (all 3 baseline-confirmed findings also confirmed by 14B v5) / REGRESSION (any missed).

- **If REGRESSION:** list which finding(s) failed, best stage reached, and the single most likely root cause based on the attempt logs (model generated something close but off? completely wrong harness? sandbox error?). One paragraph is enough — don't try to fix it.

### Stop conditions
- OOM at load → stop and report
- Total runtime > 2 hours → stop whatever is pending, write the partial report
- Any single attempt > 10 min → log it and skip that attempt only, continue

**Do NOT** attempt to fix a regression inside this task — just report it so we can diagnose together.

Commit `runs/regression-14b-v5/` to the current branch when done. Do not commit any temporary edits to source (step 3 revert).
