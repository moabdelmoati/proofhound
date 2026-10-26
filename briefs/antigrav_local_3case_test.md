# Antigravity Task — Local 14B v5 Validation (3 cases)

**Goal:** Before committing to a paid cloud GPU for the full 35-case eval, validate on 3 specific cases locally that:
1. The 14B v5 adapter actually improves over the 7B v4 baseline (not worse, not the same).
2. All three Phase 3 features (class-aware seeds, rejection sampling, call-chain v2) actually fire during a real run — not just pass unit tests.

Total expected runtime: ~45–60 minutes of GPU time. Zero cost.

**Context:**
- Current branch: `distill/v4-cloud` with `origin/phase3-features` merged in.
- Adapter: `models/harness-adapter-14b-v5/` (trained on 20 Claude+Gemini trajectories).
- Last smoke test: 14B loads on RTX 4050 (5.78/6 GB VRAM), ~0.6 tok/s, ~19 min per finding with 5 rejection-sampling attempts.
- The previous smoke on `aaptjs_1.3.1` gave 0 reached because the sandbox refuses `fs.chmodSync` (`EROFS`) — a case-specific issue, not a model issue. These 3 cases avoid that trap.

---

## The 3 test cases

| Case | Why | 7B v4 baseline (from `runs/compare-v4-full/attempts_local-harness.jsonl`) |
| --- | --- | --- |
| `arpping_2.0.0` | We have confirmed Claude + Gemini trajectories here (Phase 1 POC). 7B v4 did not confirm. Tests whether 14B v5 learned the pattern. | reached=0, confirmed=0 (loaded_not_reached) |
| `asset-cache_0.0.6` | 7B v4 **did** confirm this one (2 findings, path-traversal). Regression test — 14B v5 must at least match this. | **confirmed=2 (both path-traversal)** |
| `blamer_0.1.13` | 7B v4 confirmed one cmd-injection here. Second regression test. | **confirmed=1 (command-injection)** |

**Pass criteria:**
- `asset-cache_0.0.6` → 14B v5 confirms **≥1** of the two path-traversal findings. (If 0, 14B is worse than 7B on a known-solvable case → stop and investigate.)
- `blamer_0.1.13` → 14B v5 confirms **≥1** finding. (Same regression check.)
- `arpping_2.0.0` → ideally confirms the cmd-injection finding (which 7B v4 missed). If it reaches but doesn't confirm, that's still a win.

---

## Steps

### 1. Pre-flight checks (don't skip)
- Confirm the inference server is NOT already running (`netstat -ano | findstr :8000`). If it is, kill it to free VRAM.
- Confirm `models/harness-adapter-14b-v5/adapter_model.safetensors` exists.
- Confirm `data/seeds/*.json` are present (4 files).
- `git log --oneline -5` to confirm `phase3-features` is merged.

### 2. Prepare a targeted cases directory
Compare.py sweeps the whole `benchmark/cases/` directory. Running it over all 35 cases would take days on this GPU. Instead:
- Create a temporary dir `.trash_cleanup/cases_3/` and put symlinks (Windows `mklink /D` or copy-dir) to just the 3 target cases there:
  - `.trash_cleanup/cases_3/arpping_2.0.0 -> benchmark/cases/arpping_2.0.0`
  - `.trash_cleanup/cases_3/asset-cache_0.0.6 -> benchmark/cases/asset-cache_0.0.6`
  - `.trash_cleanup/cases_3/blamer_0.1.13 -> benchmark/cases/blamer_0.1.13`
- Point `--cases` at this directory in step 4.
- If symlinks are a hassle on Windows, just `xcopy /E /I /Q` the three case dirs into `.trash_cleanup/cases_3/`.

### 3. Start the 14B inference server
```
.venv/Scripts/python.exe training/serve/serve_local.py \
    --adapter models/harness-adapter-14b-v5 \
    --base unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit \
    --device cuda --load-4bit --port 8000 \
    > .trash_cleanup/serve-14b.log 2>&1 &
```
Wait for `"model ready"` in the log (up to 5 min — base model is already cached locally from the previous smoke test, so this should be faster this time).

### 4. Run compare.py on the 3 cases with ALL Phase 3 features
```
.venv/Scripts/python.exe -m proofhound.evaluation.compare \
    --models local-harness \
    --cases .trash_cleanup/cases_3 \
    --out runs/validate-14b-v5-3case \
    --class-seeds \
    --rejection-sampling \
    --call-chain-v2 \
    --progress-every 1
```

Expected duration: 45–75 minutes. Each finding takes ~15 min (5 attempts × ~3 min at ~0.6 tok/s). The three cases together have roughly 3–8 findings depending on how many SAST hits each one has.

### 5. Verify Phase 3 features actually ran
After the run finishes, verify each feature left evidence:

- **Class-aware seeds:** List the `corpus/` dir of any finding in the run output: `ls runs/validate-14b-v5-3case/arpping_2.0.0/*/local-harness/corpus/ | wc -l` — should be ≥20 (the seeds got written). Confirm one filename matches sha1-prefix pattern.
- **Rejection sampling:** `jq '.attempt | select(. > 1)' runs/validate-14b-v5-3case/attempts_local-harness.jsonl | wc -l` — should be > 0, since rejection sampling runs multiple attempts per finding. (You can also check for a `temperature` field varying across attempts.)
- **Call-chain v2:** Grep one of the prompts in the attempts jsonl for the v2 syntax marker (precondition / arg type): `grep -c 'precondition\|: string\|: array' runs/validate-14b-v5-3case/attempts_local-harness.jsonl` — should be > 0.

### 6. Stop the server
Kill the serve_local.py process. Verify VRAM returns to 0 with `nvidia-smi`.

### 7. Write the report
Save `runs/validate-14b-v5-3case/REPORT.md` with:

- **Per-case table:**
  | Case | Findings | 14B v5 confirmed | 7B v4 confirmed (baseline) | Verdict |
  (one row per case; 7B baseline from `runs/compare-v4-full/attempts_local-harness.jsonl`)

- **Feature-activation table:**
  | Feature | Expected evidence | Found? |
  (one row per Phase 3 feature with the specific check from step 5)

- **Per-finding details:** case, finding_id, vuln_class, best stage, best temperature (if rejection sampling found a winner), key failure reason if any.

- **Pass/fail verdict:** given the pass criteria above, is 14B v5 ready for a paid cloud eval or not?

- **If any feature failed to activate:** note which one and what the evidence trail suggests about why. Do NOT fix it in this task — just document it.

---

## Stop conditions

- **OOM at load** → something is holding VRAM. Kill all python/node processes, retry once. If it OOMs again, STOP and report.
- **A single attempt > 10 minutes** → something is wrong (not just slow). Capture the serve log and stop that one attempt only, continue the rest of the run.
- **Total runtime > 2 hours** → stop whatever is still pending and write the partial report with what completed.

Do NOT:
- Try to speed things up by reducing `--rejection-sampling` to fewer attempts — we need the full 5-attempt signal.
- Try to work around sandbox errors like `EROFS` — if a case hits one, log it as `env_blocked` in the per-case table and move on.
- Modify any source files to "fix" behavior you don't understand — flag it in the report instead.

Commit the report + attempts jsonl + summary to the current branch (`distill/v4-cloud`) once done.
