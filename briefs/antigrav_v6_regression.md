# Antigravity — v6 regression test (the decisive check)

The v6 adapter (`models/harness-adapter-14b-v6/`) was trained on 107 clean examples after we found
and fixed two faults in the v5 data: the prompts did not match what the pipeline sends, and 18
rows had leaked in from the held-out eval set. This test answers one question: does v6 match the
7B v4 baseline on the two cases v5 regressed on? If yes, the fix worked and we can justify a paid
cloud run. If no, we stop and diagnose before spending anything.

## The baseline to match

From `runs/compare-v4-full/attempts_local-harness.jsonl` (7B v4):
- `asset-cache_0.0.6` confirmed **2** findings (both path-traversal: `029e512bac`, `a55ef60143`)
- `blamer_0.1.13` confirmed **1** finding (command-injection: `971e749caf`)

v5 (the broken adapter) got **0** of these to even load. v6 must do better.

## Steps

1. Pre-flight: `netstat -ano | findstr :8000` and kill any serve process; `nvidia-smi` must show 0 MiB.
   Confirm `models/harness-adapter-14b-v6/adapter_model.safetensors` exists.

2. Build the two-case directory (symlink or `xcopy /E /I /Q`):
   `.trash_cleanup/cases_reg6/asset-cache_0.0.6` and `.trash_cleanup/cases_reg6/blamer_0.1.13`
   (sources under `benchmark/cases/`).

3. Cut rejection sampling to 3 attempts for speed. Temporarily set the default temperatures in
   `src/proofhound/core/harness/agent.py` (`produce_with_sampling`) to `[0.1, 0.3, 0.7]`.
   This is a throwaway edit — revert it before committing.

4. Start the server with the **v6** adapter:
   ```
   .venv/Scripts/python.exe training/serve/serve_local.py \
       --adapter models/harness-adapter-14b-v6 \
       --base unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit \
       --device cuda --load-4bit --port 8000 \
       > .trash_cleanup/serve-14b-v6.log 2>&1 &
   ```
   Wait for `"model ready"` (the base model is cached locally, so ~2 min).

5. Run:
   ```
   .venv/Scripts/python.exe -m proofhound.evaluation.compare \
       --models local-harness --cases .trash_cleanup/cases_reg6 \
       --out runs/reg6-14b-v6 \
       --class-seeds --rejection-sampling --call-chain-v2 --progress-every 1
   ```
   ~15 min per finding; both cases together are roughly 1.5–2 hours.

6. Kill the server, revert the temperature edit from step 3, confirm `nvidia-smi` is back to 0.

## Report — `runs/reg6-14b-v6/REPORT.md`

The one table that matters:

| Case | Finding | Class | 7B v4 | v5 | v6 | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| asset-cache_0.0.6 | 029e512bac | path-traversal | confirmed | syntax_only | ? | |
| asset-cache_0.0.6 | a55ef60143 | path-traversal | confirmed | syntax_only | ? | |
| blamer_0.1.13 | 971e749caf | command-injection | confirmed | syntax_only | ? | |

(v5 column from `runs/regression-14b-v5/`, which only reached `asset-cache`/`blamer` partially — mark
cells `not run` if v5 never got to them.)

Then a one-line verdict:
- **PASS** if v6 confirms at least 2 of the 3 baseline findings (regression fixed).
- **PARTIAL** if v6 reaches but does not confirm them (better than v5, data still thin).
- **FAIL** if v6 still only reaches `syntax_only` (the fix did not help — do not spend on cloud).

List any bonus findings in either case that v6 reached or confirmed beyond the baseline three.

Commit `runs/reg6-14b-v6/` to `distill/v4-cloud`. Do not run anything else. Stop and report the verdict.

## Hard stops
- OOM at load → report and stop.
- Any single attempt > 12 min → skip that attempt, continue.
- Total runtime > 2.5 hours → stop pending work, write the partial table.
Do not change hyperparameters, retrain, or touch `benchmark/cases/`.
