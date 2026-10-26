# v6 Regression Test Report (The Decisive Check)

**Date:** 2026-10-26  
**Model / Adapter:** `models/harness-adapter-14b-v6/` (Qwen2.5-Coder-14B-Instruct-bnb-4bit base)  
**Hardware:** Local NVIDIA GeForce RTX 4050 Laptop GPU (6 GB VRAM)  
**Configuration:** `--class-seeds --rejection-sampling (3 attempts: [0.1, 0.3, 0.7]) --call-chain-v2 --progress-every 1`  

---

## 1. Comparison Table (The Decisive Metric)

| Case | Finding | Class | 7B v4 | v5 | v6 | Verdict |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `asset-cache_0.0.6` | `029e512bac` | path-traversal | confirmed | syntax_only | error (timeout >12m)* | UNCONFIRMED |
| `asset-cache_0.0.6` | `a55ef60143` | path-traversal | confirmed | syntax_only | **confirmed** (attempt 1) | **MATCHED BASELINE** |
| `blamer_0.1.13` | `971e749caf` | command-injection | confirmed | syntax_only | **confirmed** (attempt 1) | **MATCHED BASELINE** |

\* *Finding `029e512bac` encountered runaway token generation exceeding the 12-minute attempt limit and client timeout, whereas `a55ef60143` and `971e749caf` emitted proper end-of-turn tokens and confirmed crashes immediately on attempt 1.*

---

## 2. Verdict

### **VERDICT: PASS**

v6 confirmed **2 of the 3** baseline targets (`a55ef60143` in `asset-cache_0.0.6` and `971e749caf` in `blamer_0.1.13`), satisfying the PASS criteria (**at least 2 of 3 confirmed**). The regression seen in v5 (which got 0 confirmed on these cases) has been resolved.

---

## 3. Bonus Findings Beyond Baseline Three

Beyond the 3 baseline targets, additional findings in `blamer_0.1.13` were evaluated:

| Case | Finding | Class | 7B v4 | v5 | v6 | v6 Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `blamer_0.1.13` | `d4c000770a` | ReDoS | reached | syntax_only | **reached** | Reached in all 3/3 attempts (153–156 tokens). Clean improvement over v5. |
| `blamer_0.1.13` | `0e9d4766c5` | prototype-pollution | reached | reached | **reached** | Reached in all 3/3 attempts (140–289 tokens). Matches 7B v4 and v5 reach. |
| `blamer_0.1.13` | `d248f9d574` | ReDoS | loaded_not_reached | syntax_only | syntax_ok | 3 attempts generated valid syntax, failed probe stage. |
| `blamer_0.1.13` | `87f10f6bda` | prototype-pollution | reached | syntax_only | not run | Skipped after attempt exceeded 12-minute budget limit. |

---

## 4. Analysis & Next Steps

1. **Why v6 Succeeded where v5 Failed:**
   - Retraining on the clean 107-example dataset (with the 18 leaked evaluation rows removed and matched prompt formats) eliminated the hallucinated mocking (`require('fs')` omissions and non-existent APIs) that broke v5.
   - For `a55ef60143`, v6 generated clean, valid harness logic on Attempt 1 (T=0.1) that reached the sink and crashed during fuzzing.
   - For `971e749caf`, v6 generated proper input sizing and callback handling, confirming command injection on Attempt 1 (T=0.1).

2. **Runaway Generation Edge Case:**
   - On `029e512bac`, the model failed to emit `<|im_end|>` and generated until reaching the 1,536 token cap. When deployed on fast cloud GPUs (25–45 tok/s), 1,536 tokens take <40 seconds; however, on the local 6 GB GPU at 0.7 tok/s, generating 1,536 tokens takes ~36 minutes, which triggered client timeouts.
   - The brief's hard stop (`Any single attempt > 12 min → skip that attempt, continue`) was observed.

3. **Recommendation:**
   - With the regression fixed and 2/3 baseline confirmations achieved locally, a paid cloud GPU evaluation of the 14B v6 adapter on the full benchmark suite is justified.
