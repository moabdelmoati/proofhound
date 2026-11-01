# Regression Test Report — 14B v5 Adapter (2 Cases)

**Date:** 2026-10-26  
**Model / Adapter:** `models/harness-adapter-14b-v5/` (Qwen2.5-Coder-14B-Instruct-bnb-4bit base)  
**Hardware:** Local NVIDIA GeForce RTX 4050 Laptop GPU (6 GB VRAM)  
**Execution Configuration:** `--class-seeds --rejection-sampling (3 attempts: [0.1, 0.3, 0.7]) --call-chain-v2 --progress-every 1`  
**Total Runtime:** ~80 minutes (completed end-to-end; no timeout or OOM stop conditions triggered)  

---

## 1. Regression Table (Main Deliverable)

| Case | Finding | Vuln Class | 7B v4 Baseline | 14B v5 Result | Verdict |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `asset-cache_0.0.6` | `029e512bac` | path-traversal | **confirmed** | `syntax_ok` (0/3 loaded) | **REGRESSION** |
| `asset-cache_0.0.6` | `a55ef60143` | path-traversal | **confirmed** | `syntax_ok` (0/3 loaded) | **REGRESSION** |
| `blamer_0.1.13` | `971e749caf` | command-injection | **confirmed** | `syntax_ok` (0/3 loaded) | **REGRESSION** |

---

## 2. Bonus Findings Summary

Beyond the 3 baseline-confirmed targets, 4 additional findings in `blamer_0.1.13` were evaluated:

| Case | Finding | Vuln Class | 7B v4 Baseline | 14B v5 Best Stage | Best Temperature | Reached? | Confirmed? | Notes |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `blamer_0.1.13` | `0e9d4766c5` | prototype-pollution | reached | **`reached`** | T=0.3 | **True** | False | **Positive Signal**: Attempts 2 (T=0.3) and 3 (T=0.7) both achieved `syntax_ok: True, loaded: True, reached: True` with coverage gain using `consumeRemainingAsString()`. Did not crash during fuzz budget. |
| `blamer_0.1.13` | `d248f9d574` | ReDoS | loaded_not_reached | `syntax_ok` | T=0.1 | False | False | Model attempted to invoke `target.convertStringToObject(line)` which is an unexported private function in `git.js`, failing probe with `TypeError`. |
| `blamer_0.1.13` | `d4c000770a` | ReDoS | reached | `syntax_ok` | T=0.1 | False | False | Probe stage failed across all 3 attempts (attempt 1 & 2 consumed all bytes on argument 1 leaving empty argument 2; attempt 3 unreached). |
| `blamer_0.1.13` | `87f10f6bda` | prototype-pollution | reached | `syntax_ok` | T=0.1 | False | False | Model generated valid syntax with `.catch()`, but failed probe stage due to empty second argument (`provider.consumeString(provider.remainingBytes())` consumed 100% of bytes on argument 1). |

---

## 3. Final Verdict

### **VERDICT: REGRESSION**

**Conclusion:** The 14B v5 adapter **failed all three regression checks** that the 7B v4 baseline confirmed. Although 14B v5 showed promising gains on `arpping_2.0.0` (confirming `3f6abeb009` and reaching 3 ReDoS sinks) and matched reach on `blamer` prototype-pollution (`0e9d4766c5`), it suffers from systematic regressions on known-solvable cases. **Do not proceed with paid cloud GPU evaluation until this regression is addressed.**

---

## 4. Root Cause Analysis of Regressions

A detailed review of the generated harnesses in `runs/regression-14b-v5/attempts_local-harness.jsonl` vs the 7B v4 baseline in `runs/compare-v4-full/attempts_local-harness.jsonl` reveals two distinct failure mechanisms:

1. **`asset-cache_0.0.6` (`029e512bac` & `a55ef60143`): Over-Complication / Hallucinated Mocking**
   - **7B v4 Baseline Behavior:** 7B v4 generated a simple, minimal invocation:
     ```javascript
     const provider = new FuzzedDataProvider(data);
     let url = "/" + provider.consumeString(50);
     target.loadFile(url, provider.consumeString(50), () => {});
     ```
     This loaded cleanly and confirmed path traversal immediately during fuzzing.
   - **14B v5 Regression Behavior:** 14B v5 attempted to "mock" filesystem operations at global harness scope before requiring `fs`:
     ```javascript
     const originalFsStat = fs.stat; // ReferenceError: fs is not defined!
     fs.stat = function(...) { ... };
     ```
     Across Attempts 1 and 2 for both findings, this missing `require('fs')` caused an immediate `ReferenceError` at the `probe` stage. When Attempt 3 for `a55ef60143` finally included `const fs = require('fs')`, it called a hallucinated Jazzer.js API method `provider.getBytesLeft()` (which does not exist on `FuzzedDataProvider`), failing probe with `TypeError`.

2. **`blamer_0.1.13` (`971e749caf`): Unhandled Promise Rejection & Zero-Length Arguments**
   - **7B v4 Baseline Behavior:** 7B v4 wrapped the invocation in `try { target(file, args); } catch (e) { ... }` with independent slicing of strings:
     ```javascript
     let file = provider.consumeRemainingAsString().slice(0, 256);
     let args = provider.consumeRemainingAsString().slice(0, 256);
     try { target(file, args); } catch (e) { ... }
     ```
   - **14B v5 Regression Behavior:** 14B v5 generated:
     ```javascript
     const file = provider.consumeString(provider.remainingBytes());
     const args = provider.consumeString(provider.remainingBytes());
     target(file, args);
     ```
     This has two flaws:
     - `provider.consumeString(provider.remainingBytes())` exhausts all fuzzer input on `file`, leaving `args` as an empty string (`""`), starving the command injection sink `git blame + args + realFile`.
     - `target(file, args)` returns a bluebird Promise. Without a `.catch()` rejection handler on attempts 1–3 of this finding, git execution errors triggered an unhandled Promise rejection in Node.js, failing the probe stage.

---

## 5. Deliverables

- Attempts Log: `runs/regression-14b-v5/attempts_local-harness.jsonl` (21 attempts logged)
- Summary JSON: `runs/regression-14b-v5/summary.json`
- Source Code Status: Clean (temporary `agent.py` temperature edit reverted; zero untracked diffs in `src/`).
