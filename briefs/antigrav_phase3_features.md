# Antigravity Task — Phase 3 Features Integration

**Context:** ProofHound trains a local 14B harness-generation model (MSc thesis). Phase 1 (data distillation) is done — 20 confirmed trajectories in `training/data/distill-v5-chatml.jsonl`. Phase 2 (14B QLoRA training) is running on Kaggle now. Phase 3 adds three features to boost confirmed rate without more training.

**How to use this file:** Open Antigravity with this repo open. Paste the single brief below as one task. The task implements all three features together because they integrate with the same evaluation pipeline.

---

## Brief

Implement Phase 3 features for the ProofHound harness evaluation pipeline. All three features integrate with `src/proofhound/core/harness/agent.py` and `src/proofhound/evaluation/compare.py`. Keep each feature behind a CLI flag so the baseline behavior is unchanged by default.

### Feature 1 — Class-Aware Fuzzer Seeds

**Goal:** Before fuzzing a harness, seed the Jazzer corpus directory with vulnerability-class-specific trigger patterns so libFuzzer starts from known-crashing shapes.

**Inputs:** The four JSON files already present at `data/seeds/`:
- `redos_seeds.json`
- `proto_pollution_seeds.json`
- `path_traversal_seeds.json`
- `cmd_injection_seeds.json`

Each file is `{"description": "...", "seeds": [str, ...]}`.

**Steps:**
1. Add a helper `seed_corpus(corpus_dir: Path, vuln_class: str) -> int` in a new module `src/proofhound/core/fuzzing/seeds.py`. It reads the matching JSON file, writes each seed as its own file under `corpus_dir/` (filename = sha1(seed)[:12]), and returns the count written.
2. Call it from the harness runner just before the Jazzer fuzz invocation — look at how the corpus directory is created in `src/proofhound/core/harness/check.py` and `src/proofhound/core/fuzzing/fuzzer.py`.
3. Add a `--class-seeds / --no-class-seeds` flag to `compare.py` (default true).

### Feature 2 — Rejection Sampling

**Goal:** Instead of 3 fixed attempts, generate up to 5 harnesses per finding at different temperatures. Stop on the first confirmed crash. Keep the best reached outcome if none confirms.

**Steps:**
1. In `src/proofhound/core/harness/agent.py`, add a method `produce_with_sampling(finding, target, out, temps: list[float]) -> Harness | None`:
   - Loop over `temps` (default: `[0.1, 0.3, 0.5, 0.7, 0.9]`).
   - For each temp, override the client's temperature setting, run the normal `produce()` path with max_attempts=1.
   - Short-circuit if a crash is confirmed (ask check.py to run the fuzz step inline — currently it may be deferred).
   - Return the best harness: confirmed > reached > loaded > syntax_ok.
2. Add `--rejection-sampling / --no-rejection-sampling` flag to `compare.py` (default false — keep old behavior unless flag passed).
3. The attempt log should record each attempt separately with its temperature.

### Feature 3 — Static Precomputation v2

**Goal:** Enrich the v4 call-chain prompt with argument types and preconditions per step.

**Steps:**
1. Open `src/proofhound/core/analysis/call_chain.py`. The current `extract_call_chain(target, finding)` returns a list of steps (function name + line). Extend each step to also include:
   - `arg_types`: inferred by looking at how each parameter is used inside the function body (via tree-sitter) — "string" if indexed/concatenated/compared, "array" if iterated, "object" if accessed via `.property`, "number" if arithmetic, otherwise "unknown".
   - `preconditions`: any `if (!x) return`, `assert`, type checks (`typeof`, `Array.isArray`) at the top of the function body.
2. Update the prompt builder in `src/proofhound/core/harness/agent.py` (search for where the call chain is injected into the prompt) to render these extra fields in a compact format, e.g.:
   ```
   Call chain:
     1. ping(range: array)  — precondition: Array.isArray(range) && range.length
     2. exec(cmd: string, cb: function)  — sink
   ```
3. Keep the old format behind a flag: `--call-chain-v2 / --call-chain-v1` (default v2).

### Testing

After implementing all three, run on a known-good finding to verify the pipeline still works end-to-end:
```
.venv/Scripts/python.exe -m proofhound.evaluation.compare \
    --models local-harness \
    --cases benchmark/cases \
    --max-cases 1 \
    --out runs/phase3-smoke \
    --class-seeds \
    --rejection-sampling \
    --call-chain-v2
```

The server at port 8000 may not be running (local 7B inference), so the smoke test can fail at the model call step — that is fine; the goal is to verify the arguments parse, the seeds get written to the corpus directory, and no `ImportError` fires.

### Done = all three true

1. All three flags work on `compare.py --help`.
2. `data/seeds/*.json` get loaded and written to the corpus directory when `--class-seeds` is on (verify by inspecting `runs/phase3-smoke/<case>/<finding>/local-harness/corpus/` after a smoke run).
3. The call chain in a sample prompt (print it from `agent.py` with a debug statement for one finding) shows arg types + preconditions.

Commit everything to a new branch `phase3-features` and push.
