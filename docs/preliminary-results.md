# ProofHound — Preliminary End-to-End Results (Term 1)

First real run of the full pipeline with an LLM (claude-sonnet-5 via CodeCraft) on a 6-case
subset of the benchmark. Raw data: `experiments/results/pipeline_subset.json`.

## Setup

- Model: `claude-sonnet-5` (the smallest Claude on CodeCraft), guided mode (SAST source/sink in
  the prompt), repair budget 2, fuzz 30 s per target, 3× crash reproduction.
- 6 cases, 2 vulnerability classes (command-injection, path-traversal), both commit modes.

## Results

| Case | Class | Findings | Harness ok | 1st-try | Confirmed | Detected (file+class) |
|---|---|---|---|---|---|---|
| dns-sync | command-injection | 1 | 1 | 1 | 1* | no |
| diskusage-ng | command-injection | 1 | 1 | 0 | 1 | yes |
| apex-publish-static-files | command-injection | 1 | 1 | 0 | 1 | yes |
| vivaxy-here | path-traversal | 1 | 1 | 0 | 1 | yes |
| asset-cache | path-traversal | 2 | 2 | 0 | 2 | yes |
| command-exists | command-injection | 4 | 2 | 2 | 1 | yes |
| **total** | | **10** | **8** | **3** | **7** | **5 / 6 cases** |

\* dns-sync's harness confirmed a *prototype-pollution* crash (a different class, no frame in the
package), not the command injection SAST flagged — see "Honest notes".

## Headline numbers

- **RQ1 — harness success (guided):** 8/10 findings produced a validated harness (**80%**);
  **3/10 (30%)** validated on the first attempt, the rest after repair.
- **End-to-end detection:** **5/6 cases** confirmed the ground-truth vulnerability (same file and
  class), each with a reproducing input and confidence ≥ 0.90. With the stricter ±2-line metric it
  is 4/6 — asset-cache differs only in which line of the same function the crash is attributed to
  (Jazzer: `path.join` line 22; SecBench: `fs.readFile` line 31 — the same path-traversal).
- **Cost:** **86,693 tokens** for all 6 cases (~14k/case), ~18 min total.

## Honest notes (threats to validity / Term 2 improvements)

1. **Cross-class confirmations.** The fuzzer runs with all bug detectors enabled, so a
   command-injection harness can trip the prototype-pollution detector (dns-sync). The triage
   fusion correctly downgrades a class mismatch to 0.90→0.70 confidence, and the detection metric
   (same file + class) excludes it, so it is not counted as a true detection. **Term 2:** run
   class-targeted fuzzing (enable only the finding's detector) to remove these.
2. **Line attribution.** A sink spread across a function is attributed by Jazzer to the actual
   fs/exec call site, which can differ from SecBench's recorded line. "Same file + class" is the
   honest detection metric; strict line matching undercounts.
3. **Subset bias.** These 6 cases were pre-selected as SAST-detected and low-finding (to bound
   cost), so this subset speaks to RQ1 (harness success) and end-to-end confirmation, not to the
   false-positive-reduction story — that is the full SAST benchmark (244 candidates across 31
   cases, §Term 1 report).

## What this establishes

The full pipeline works end to end with a real LLM: SAST → LLM harness → sandbox fuzzing →
reproduced crash → fused confidence, on real npm packages, at low cost. These are the first RQ1
numbers and the training data for the pilot model; the next step is the full benchmark run.
