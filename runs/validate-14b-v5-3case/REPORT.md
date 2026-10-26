# Local 14B v5 Validation Report (3 Cases)

**Date:** 2026-10-26  
**Adapter:** `models/harness-adapter-14b-v5/` (Qwen2.5-Coder-14B-Instruct-bnb-4bit base)  
**Hardware:** Local NVIDIA GeForce RTX 4050 Laptop GPU (6 GB VRAM)  
**Execution Flags:** `--class-seeds --rejection-sampling --call-chain-v2 --progress-every 1`  
**Run Mode:** Partial run stopped at 2-hour limit per brief stop conditions  

---

## 1. Executive Summary

This validation run tested whether the fine-tuned 14B v5 adapter improves over the 7B v4 baseline and verified that all Phase 3 features activate during live evaluation before committing to a paid cloud GPU evaluation.

- **Stop Condition Triggered:** **Total runtime > 2 hours** (Task started 01:35:27 local, stopped 03:35:00 local). Generation speed on the RTX 4050 averaged ~0.7 tok/s (~4.5 minutes per attempt). Because `arpping_2.0.0` contained 7 findings (2 command-injection, 5 ReDoS) and ran up to 5 rejection-sampling attempts per unconfirmed finding (~22 minutes each), the 2-hour budget was exhausted during Finding 6 of `arpping_2.0.0`.
- **Key Validation Result on `arpping_2.0.0`:** **CONFIRMED WIN.**
  - 14B v5 confirmed command-injection finding `3f6abeb009` on **Attempt 1** (`crash_confirmed: True`, 211.5s). Baseline 7B v4 completely failed to reach it (`reached=0, confirmed=0`).
  - 14B v5 successfully **reached target** on 3 ReDoS findings (`13f29f7ad6`, `d743fff5e2`, `e0d434123c`) where 7B v4 had 0 reaches.
- **Phase 3 Features:** **All 3 features actively fired and left verified evidence.**

---

## 2. Per-Case Table

| Case | Total Findings in Case | Findings Evaluated | 14B v5 Confirmed | 7B v4 Confirmed (Baseline) | Verdict |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `arpping_2.0.0` | 7 | 6 (5 complete, 1 partial) | **1** (`3f6abeb009`) | 0 (7B v4 missed: `reached=0, confirmed=0`) | **PASS (Outperformed baseline; reached 3 ReDoS targets)** |
| `asset-cache_0.0.6` | 2 | 0 | Pending | 2 (both path-traversal) | **PENDING (Interrupted by 2-hour stop condition)** |
| `blamer_0.1.13` | 5 | 0 | Pending | 1 (command-injection) | **PENDING (Interrupted by 2-hour stop condition)** |

*Note: Baseline 7B v4 numbers sourced directly from `runs/compare-v4-full/summary.json` and `attempts_local-harness.jsonl`.*

---

## 3. Feature-Activation Table

| Feature | Expected Evidence | Found? | Details / Metrics |
| :--- | :--- | :---: | :--- |
| **Class-Aware Seeds** | `runs/validate-14b-v5-3case/arpping_2.0.0/*/local-harness/corpus/` contains $\ge 20$ files matching SHA-1 prefix pattern | **YES** | Exactly 20 seed files verified per corpus directory (e.g. `0285556b17c1`, `35afa6adf199`, `fd9c9a428a45`). Probe logs confirmed `20 files found in /work/out/corpus`. |
| **Rejection Sampling** | `jq '.attempt \| select(. > 1)' attempts_local-harness.jsonl` $> 0$; varying `temperature` across attempts | **YES** | 18 attempts with `attempt > 1` (out of 24 total attempts). Temperatures stepped predictably across attempts: `[0.1, 0.3, 0.5, 0.7, 0.9]`. Directly enabled reaching targets on `13f29f7ad6` (T=0.3) and `d743fff5e2` (T=0.5) after T=0.1 failed probe. |
| **Call-Chain v2** | `grep -c 'precondition\|: string\|: array' attempts_local-harness.jsonl` $> 0$ | **YES** | Present in **24 of 24 prompts** (100%). Explicit type annotations (`ping(range: array)`, `exec(cmd: string, cb: function) — sink`) and preconditions (`precondition: Array.isArray(range) && range.length`) rendered into harness prompt templates. |

---

## 4. Per-Finding Details (`arpping_2.0.0`)

| Finding ID | Vulnerability Class | Attempts Evaluated | Best Stage | Best Temperature | Reached? | Confirmed? | Key Details & Failure Modes |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| `cb8fdc7130` | command-injection | 5 | `syntax_ok` | T=0.1 | False | False | Model generated valid JavaScript syntax across all 5 attempts, but failed at the `probe` stage due to calling nonexistent Jazzer.js helper methods (e.g. `provider.consumeInt32InRange`). |
| `3f6abeb009` | command-injection | 1 | **`confirmed`** | **T=0.1** | **True** | **True** | **Confirmed on Attempt 1** in 211.5s. Accurately constructed `arppingInstance.arp(range).catch(...)` with fuzzer data provider. Triggered command injection crash. Baseline 7B v4 had failed to reach. |
| `13f29f7ad6` | ReDoS | 5 | **`reached`** | **T=0.3** | **True** | False | Attempt 1 failed probe; Attempts 2 (T=0.3), 3 (T=0.5), and 4 (T=0.7) all achieved `syntax_ok: True, loaded: True, reached: True` with coverage gain. Did not crash during fuzz budget (ReDoS requires catastrophic backtracking input). Baseline 7B v4 reached=0. |
| `d743fff5e2` | ReDoS | 5 | **`reached`** | **T=0.5** | **True** | False | Attempts 1 & 2 failed probe; Attempts 3 (T=0.5), 4 (T=0.7), and 5 (T=0.9) achieved `reached: True`. Rejection sampling temperature ramp directly rescued the finding. Baseline 7B v4 reached=0. |
| `e0d434123c` | ReDoS | 5 | **`reached`** | **T=0.1** | **True** | False | Attempts 1 (T=0.1), 2 (T=0.3), and 3 (T=0.5) achieved `reached: True` on `findMyInfo() -> trim()`. Reached target; no crash confirmed. Baseline 7B v4 reached=0. |
| `cab298854d` | ReDoS | 3 (partial) | `syntax_ok` | T=0.1 | False | False | Attempts 1–3 generated valid syntax but failed probe due to calling `provider.consumeInt` (Jazzer.js requires `consumeIntegralInRange`). Evaluation stopped at attempt 3 when 2-hour limit was reached. |
| `24f41ac1d0` | ReDoS | 0 | `pending` | N/A | N/A | N/A | Not evaluated due to 2-hour limit. |

---

## 5. Pass/Fail Verdict & Recommendation

### Verdict: **QUALIFIED PASS — READY FOR PAID CLOUD EVALUATION**

**Rationale:**
1. **Pass Criteria on `arpping_2.0.0` was Fully Satisfied:**
   - Brief specification: *"arpping_2.0.0 → ideally confirms the cmd-injection finding (which 7B v4 missed). If it reaches but doesn't confirm, that's still a win."*
   - Outcome: 14B v5 **confirmed** `3f6abeb009` on its very first attempt, and reached target on 3 ReDoS findings where 7B v4 had 0 reaches. The 14B v5 adapter clearly learned the target harness construction pattern demonstrated in the training trajectories.
2. **Phase 3 Features Proven in Live Pipeline:**
   - All three Phase 3 capabilities (class-aware seeds, rejection sampling with temperature escalation, call-chain v2 prompts) functioned seamlessly together end-to-end without bugs or crashes.
3. **Local Hardware Constraint Justifies Cloud Run:**
   - Generating 14B at 4-bit precision on the local RTX 4050 yields ~0.7–0.8 tokens/second (~4.5 minutes per attempt). Running full 5-attempt rejection sampling across multiple findings per case makes local evaluation of multi-case suites prohibitively slow.
   - On a cloud GPU (e.g. A10G or L4 at ~30–40 tok/s), each attempt will take ~5–10 seconds instead of 270 seconds. The full 35-case benchmark will complete within standard evaluation budgets.
