# ProofHound

## Agentic Vulnerability Discovery and Repair — *Stop Guessing, Start Proving Vulnerabilities*

Graduation Project and Research Proposal — updated to reflect the Term 1 implementation and an
expanded, 5-person scope.

---

## 1. Abstract

Static analysis (SAST) finds vulnerability candidates quickly but reports many false positives,
while fuzzing confirms real defects by execution but depends on hand-written harnesses. We build
**ProofHound**, a multi-agent framework that connects the two: SAST findings on changed code guide
a large language model (LLM) to write a fuzz harness, a coverage-guided fuzzer executes it in a
sandbox, and a triage stage fuses both signals into one confidence score, generates a
proof-of-vulnerability (PoV), and proposes a patch that is accepted only if re-fuzzing confirms the
fix. Several agents run on our own small models, fine-tuned on Colab with QLoRA, working alongside
a large model in a cascade: our models act first, execution checks the result, and the large model
steps in only when needed. The system runs on every commit or merge request. It starts with
JavaScript/TypeScript and adds Python. The project delivers a working tool, a reproducible
benchmark, and an experimental study suitable for a research paper.

## 2. Problem Statement

Developers often ignore SAST output because a large share of alerts are not real bugs. Fuzzing is
the standard way to confirm a defect, but writing the harness requires expertise and time. The
JavaScript/npm ecosystem, where packages are widely reused, has little comparable LLM-fuzzing
tooling. We ask: how can static and dynamic evidence be combined, automatically and per commit, so
that reported vulnerabilities are confirmed, prioritized, and repaired with low false-positive cost?

**Early evidence from our own benchmark.** On 11 real npm vulnerabilities (SecBench.js), our SAST
rules alone flag the true sink in **11/11** cases but also raise **58** candidate findings inside
the changed functions — a false-positive load that motivates execution-based confirmation
directly (see §8).

## 3. Objectives

1. A per-commit pipeline that analyzes only changed functions, confirms findings by fuzzing, and
   reports a reproducing input.
2. SAST-guided LLM harness generation with an automatic repair loop for failed harnesses.
3. A fused SAST + fuzzing confidence score, a PoV, and a CVSS estimate per confirmed finding.
4. Patches and regression tests accepted only if the PoV no longer triggers and tests still pass.
5. Evaluation against SAST-only, fuzzing-only, and single-agent baselines on real npm bugs.
6. Generalization to Python as a second fuzzed language.
7. Our own fine-tuned agent models (Harness, Patcher, Triage, Analyzer filter) in a cascade with a
   large model that steps in only when they fail or are uncertain.

## 4. System

A pipeline of cooperating agents controlled by an orchestrator that keeps state, retries, and
per-run time and token budgets. All generated code runs in Docker containers without network access
and with CPU, memory, and process limits.

| Component | Role |
|---|---|
| **Analyzer** | Extracts changed functions from the diff and runs SAST on them (source, sink, severity). |
| **Scheduler** | Assigns fuzzing time by severity and reuses the stored corpus (rule-based). |
| **Harness** | Writes a harness guided by the finding; feeds compile/runtime errors back for repair. |
| **Fuzzer** | Runs the coverage-guided fuzzer in the sandbox, monitors coverage and crashes, updates the corpus. |
| **Triage** | Deduplicates crashes, fuses SAST and fuzzing evidence into one confidence, generates the PoV, estimates CVSS. |
| **Patcher** | Proposes a patch and regression test; validates by re-running the PoV and the test suite. |
| **Orchestrator** | Coordinates agents, enforces budgets, stores results, emits reports (MR comment, SARIF, JSON). |

SAST is accessed through an interface; the initial engine is Semgrep, with our own engine as a
pluggable alternative. A per-language adapter isolates everything language-specific, so a new
language needs one adapter and no change to the agents.

## 5. Cascade: our models alongside a large model

Our small models are not meant to replace the large model; they work in a cascade: our model acts
first, the result is checked, and the large model steps in only when the check fails or our model is
uncertain. We use one open code base model (1.5B–7B, chosen in the literature review) with a
separate LoRA adapter per agent, trained with QLoRA on Colab, so several agents share one base model
at low cost.

Where a result can be verified by running it (Harness, Patcher), **execution is the judge** rather
than another model. The large model reviews only decisions with no execution check (Triage, Analyzer
filter) and acts as the teacher that produces training data via verified distillation.

## 6. Data

Evaluation and training data are kept strictly separate: a package used in the benchmark never
appears in training data.

| Purpose | Source |
|---|---|
| JS/TS benchmark | SecBench.js, extended with recent npm advisories from OSV / GitHub Advisory DB |
| Python benchmark | PyPA advisory database and OSV |
| Patcher training | CVEfixes and upstream fix commits |
| Harness training | Functions from popular npm packages; harnesses from OSS-Fuzz as seed examples (verified distillation) |
| Triage / Analyzer training | Labeled automatically by our own pipeline runs |
| Demo | OWASP NodeGoat and Juice Shop, plus injected cases |

## 7. Supported languages

| Language | Fuzzer | Status |
|---|---|---|
| JavaScript / TypeScript | Jazzer.js | Core, fully evaluated |
| Python | Atheris | Second language; analysis side implemented, fuzzing in Term 2 |
| Go (optional) | `go test -fuzz` | If time allows |
| C / C++ | libFuzzer / AFL++ | Future work |

## 8. Research questions

- **RQ1** Does SAST-guided harness generation raise first-attempt harness success and detection
  rate vs. unguided generation?
- **RQ2** Does fusing SAST and fuzzing evidence reduce false positives vs. either alone?
- **RQ3** Does the multi-agent design outperform a single agent with the same model and tools, at
  comparable cost?
- **RQ4** What does each module (scheduling, repair loop, fusion, patch validation) contribute?
- **RQ5** Do results generalize when Python is added, with minimal change to the agents?
- **RQ6** In the cascade, what share of work do our models complete without the large model, how
  much cost and time does that save, and does detection stay comparable?

Metrics: harness success on first attempt and after repair, target-reachability, detection rate,
false-positive rate, fused-score precision, patch correctness, share of work done by our models,
cost saved, and time and tokens per commit. All prompts, model versions, and seeds are logged so
experiments can be repeated.

## 9. Implementation status (Term 1)

Implemented and tested end to end on real npm vulnerabilities:

- Docker fuzzing sandbox (Jazzer.js), no network, resource-limited.
- Diff parser and tree-sitter changed-function extraction for JS/TS **and Python**.
- Analyzer with Semgrep taint rules for **five** vulnerability classes (command injection, path
  traversal, code injection, prototype pollution, ReDoS).
- Fuzzer agent with 3× crash reproduction (only reproducible, class-matching crashes count).
- Orchestrator, CLI (`analyze`, `scan`, `benchmark-sast`), JSON and **SARIF** reports.
- **GitHub Action** that runs ProofHound on pull requests and uploads results to code scanning.
- **Triage fusion score** (rule-based SAST + fuzzing → confidence), the RQ2 core.
- Benchmark builder turning SecBench.js cases into two-commit repos with ground truth; an initial
  benchmark; training-data logging of every harness attempt; a pilot QLoRA notebook.

The Harness Agent (LLM prompt and repair loop) is authored by the team.

## 10. Expanded scope for a 5-person team

Pulled earlier from the original Term 2 plan and added on top:

- SARIF + GitHub Action per-commit integration (done).
- Python analysis side via the adapter layer (done); Python fuzzing with Atheris (Term 2).
- Triage fusion score (done); full triage with PoV + CVSS (Term 2).
- Five vulnerability classes instead of two.
- Larger benchmark (target 40–50 cases) and a dedicated false-positive study.
- Optional: a second SAST engine (e.g. CodeQL) for comparison, and a results dashboard.

## 11. Team roles

| Member | Term 1 | Term 2 |
|---|---|---|
| 1 — Harness / LLM | Harness Agent and repair loop; run on the benchmark | Cascade and large-model escalation; RQ1/RQ3 |
| 2 — SAST / Analyzer | More Semgrep rule classes; false-positive analysis | Python analysis; optional CodeQL comparison |
| 3 — Fuzzing / Sandbox | Fuzzer, sandbox, benchmark construction | Full triage (PoV + CVSS); continuous fuzzing |
| 4 — Infra / Integration | SARIF, CLI, CI/GitHub Action, dashboard | Patcher; Python fuzzing (Atheris); Go if time |
| 5 — ML / Research | Literature review; base-model selection; training data | Train LoRA adapters; RQ6; paper writing |

## 12. Deliverables and risks

**Deliverables:** an open-source tool (CLI and CI integration), our fine-tuned agent models and
their training datasets, a benchmark with ground truth, a research-paper draft, and the graduation
report.

**Risks and mitigations:** harness generation is the hardest part — start with simple pure
functions and widen; fuzzing is slow — fixed time budgets and corpus reuse; our models may handle
little of the work or Colab may limit training — the large model covers every failure, so results
stay correct, and we report the share honestly; scope growth — a fixed protected core with
extensions ordered by priority.
