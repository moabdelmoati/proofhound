# v6 Training Dataset & Retrain Report

**Date:** 2026-10-26  
**Dataset:** `training/data/harness_train_v6.jsonl`  
**Kernel:** `ebbrewqvqv/proofhound-harness-14b-v5` (Version 5)  

---

## 1. Dataset Leak Fix Summary (Job 1)

In `scripts/build_training_v6.py`, the builder was writing `"split": "train"` statically on every row without checking the case's manifest (`case.yaml`). This inadvertently included 18 rows from `benchmark/cases/` (the held-out evaluation set from `"source": "distillation-v5"`).

**Fixes Applied:**
1. Added module-level helper `case_split(case)` to inspect `case.yaml` across `training/cases/` and `benchmark/cases/`.
2. Updated both `source_a` and `source_b` to populate `"split": case_split(case)`.
3. Added a leak guard filter in `main()`: dropped 20 non-train rows.
4. Added an assertion guard: `assert all(r.get("split") == "train" for r in rows)`.
5. Gate verification executed: `rows 107 leaked 0` (0 benchmark cases present).

---

## 2. Dataset Metrics

- **Total Examples:** 107 rows (all `split: train`)
- **Vulnerability Class Distribution:**
  - `path-traversal`: 44
  - `command-injection`: 32
  - `prototype-pollution`: 31
- **Source Breakdown:**
  - `distillation-v1`: 107 (100% clean training cases)
- **Pipeline Prompt Byte-for-Byte Verification:** **8** prompts verified identical to saved live pipeline logs:
  - `compare-v4-full`: 5
  - `regression-14b-v5`: 1
  - `smoke-14b-v5`: 1
  - `validate-14b-v5-3case`: 1

---

## 3. Kaggle Training Run (Job 2)

- **Dataset Version:** Uploaded to `ebbrewqvqv/proofhound-harness-data` with message `"v6 clean: train split only"`.
- **Kernel Push:** Pushed to `ebbrewqvqv/proofhound-harness-14b-v5` (Version 5) on dual T4 GPUs (`GpuT4x2`).
- **Hyperparameters:** Unchanged from v5 baseline (EPOCHS=3, batch settings isolated to test data effect only).
- **Current Status:** `KernelWorkerStatus.RUNNING`
