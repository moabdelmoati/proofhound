# ProofHound

## Agentic Vulnerability Discovery and Repair — *Stop Guessing, Start Proving Vulnerabilities*

Graduation Project and Research Proposal. Updated to reflect the Term 1 implementation, a
single-agent → multi-agent research spine, and an expanded, 5-person scope.

---

## 1. Abstract

Static analysis (SAST) finds vulnerability candidates quickly but reports many false positives,
while fuzzing confirms real defects by execution but depends on hand-written harnesses. We build
**ProofHound**, a framework that connects the two: SAST findings on changed code guide a large
language model (LLM) to write a fuzz harness, a coverage-guided fuzzer executes it in a sandbox, a
triage stage fuses both signals into one confidence score and a proof-of-vulnerability (PoV), and
the system then proposes a code fix that is accepted only if re-fuzzing confirms it is gone.

The central research question is whether a **team of specialized agents** confirms and repairs more
vulnerabilities, at comparable cost, than a **single general agent** with the same model and tools.
We answer it across two terms: Term 1 delivers the shared infrastructure and a working
**single-agent** system end to end; Term 2 adds the **multi-agent** system and a head-to-head
comparison, plus our own small models (fine-tuned on Colab with QLoRA) in a cascade with a large
model. The system runs on every commit or merge request, starts with JavaScript/TypeScript, and
adds Python. It delivers a working tool, a self-hosted dashboard, a reproducible benchmark, and an
experimental study suitable for a research paper.

## 2. Problem Statement

Developers often ignore SAST output because a large share of alerts are not real bugs. Fuzzing is
the standard way to confirm a defect, but writing the harness requires expertise and time. The
JavaScript/npm ecosystem, where packages are widely reused, has little comparable LLM-fuzzing
tooling. We ask: how can static and dynamic evidence be combined, automatically and per commit, so
that reported vulnerabilities are confirmed, prioritized, and repaired with low false-positive cost
— and does splitting the work across specialized agents beat a single agent?

**Early evidence from our own benchmark.** On **31** real npm vulnerabilities (built from
SecBench.js), our SAST rules alone flag the true sink in **30/31** cases but also raise **244**
candidate findings inside the changed functions (about **7.9 false positives per case**). That
false-positive load is the direct motivation for confirming findings by execution before showing
them to a developer.

## 3. The research spine: single agent vs. multi-agent

- **Single agent (Term 1).** One LLM is given the changed code, the SAST finding, and a set of
  tools (read file, run SAST, write a harness, run the fuzzer, propose a fix). It decides the whole
  flow itself in one loop.
- **Multi-agent (Term 2).** The same work is split across specialized agents — Analyzer, Scheduler,
  Harness, Fuzzer, Triage, Patcher — each with a fixed role, prompt, and tools, coordinated by an
  orchestrator, with our own small models in a cascade under a large model.

Both share the same infrastructure (sandbox, SAST, fuzzer, benchmark, reports), so the comparison
isolates the effect of the agent architecture itself. This is **RQ3**, promoted to the backbone of
the project.

## 4. Objectives

1. Shared per-commit infrastructure: analyze only changed functions, confirm findings by fuzzing in
   a sandbox, and report a reproducing input. *(Term 1)*
2. A working single-agent system end to end on JS/TS. *(Term 1)*
3. SAST-guided harness generation with an automatic repair loop. *(both; single-loop in Term 1)*
4. A fused SAST + fuzzing confidence score and a PoV per confirmed finding. *(Term 1 score; full PoV
   in Term 2)*
5. Automatic code repair: propose a fix, accepted only if the PoV no longer triggers and existing
   tests still pass. *(Term 2)*
6. The multi-agent system and a rigorous single-agent vs. multi-agent comparison (RQ3). *(Term 2)*
7. Our own fine-tuned models in a cascade with a large model that steps in only on failure or
   uncertainty. *(pilot in Term 1, full in Term 2)*
8. A self-hosted dashboard that shows, per scanned project, every confirmed vulnerability and
   whether it was fixed — with all data staying inside the organization. *(Term 2)*
9. Generalization to Python as a second fuzzed language. *(Term 2)*

## 5. System

A pipeline of components controlled by an orchestrator that keeps state, retries, and per-run time
and token budgets. All generated code runs in Docker containers without network access and with
CPU, memory, and process limits. The single agent and the multi-agent system are two front-ends
over the same components.

| Component | Role |
|---|---|
| **Analyzer** | Extracts changed functions from the diff and runs SAST on them (source, sink, severity). |
| **Scheduler** | Assigns fuzzing time by severity and reuses the stored corpus (rule-based). |
| **Harness** | Writes a harness guided by the finding; feeds compile/runtime errors back for repair. |
| **Fuzzer** | Runs the coverage-guided fuzzer in the sandbox; monitors coverage and crashes; updates the corpus. |
| **Triage** | Deduplicates crashes, fuses SAST and fuzzing evidence into one confidence, generates the PoV, estimates CVSS. |
| **Patcher** | Proposes a code fix and a regression test; validates by re-running the PoV and the test suite. |
| **Orchestrator** | Coordinates the flow, enforces budgets, stores results, emits reports (dashboard, SARIF, JSON, MR comment). |

SAST is accessed through an interface (Semgrep first, our own engine pluggable). A per-language
adapter isolates everything language-specific, so a new language needs one adapter and no change to
the components.

## 6. New capabilities requested for this scope

- **Easier scanning.** One command (`proofhound scan`), a GitHub Action that runs on every pull
  request, and a pre-commit/CI entry point, so a team adopts ProofHound without wiring anything by
  hand. Results appear inline in the code-scanning view via SARIF.
- **Automatic code repair.** After a finding is confirmed by a reproduced crash, the Patcher
  proposes a minimal edit to the vulnerable function plus a regression test. The edit is accepted
  only if, after applying it, the PoV no longer triggers and the project's existing tests still
  pass — execution is the judge, never the model's say-so.
- **Self-hosted dashboard.** A web dashboard, deployed inside the organization, lists each scanned
  project (web apps and services) with its confirmed vulnerabilities, their severity and PoV, and
  which ones have been fixed. **Privacy by design:** the dashboard and the whole pipeline run on the
  organization's own machines; source code, findings, and PoVs never leave its network, and the
  only external call is the optional large-model API (which can be swapped for a self-hosted model).

## 7. Cascade: our models alongside a large model

Our small models work in a cascade: our model acts first, the result is checked, and the large model
steps in only when the check fails or our model is uncertain. We use one open code base model
(1.5B–7B) with a separate LoRA adapter per agent, trained with QLoRA on Colab, so several agents
share one base model at low cost. Where a result can be verified by running it (Harness, Patcher),
execution is the judge; the large model reviews only decisions with no execution check (Triage,
Analyzer filter) and acts as the teacher that produces training data via verified distillation.

## 8. Data

Evaluation and training data are kept strictly separate: a package used in the benchmark never
appears in training data.

| Purpose | Source |
|---|---|
| JS/TS benchmark | SecBench.js, extended with recent npm advisories from OSV / GitHub Advisory DB |
| Python benchmark | PyPA advisory database and OSV |
| Patcher training | CVEfixes and upstream fix commits |
| Harness training | Functions from popular npm packages; OSS-Fuzz harnesses as seeds (verified distillation) |
| Triage / Analyzer training | Labeled automatically by our own pipeline runs |
| Demo | OWASP NodeGoat and Juice Shop, plus injected cases |

## 9. Supported languages

| Language | Fuzzer | Status |
|---|---|---|
| JavaScript / TypeScript | Jazzer.js | Core, fully evaluated |
| Python | Atheris | Analysis side implemented; fuzzing in Term 2 |
| Go (optional) | `go test -fuzz` | If time allows |
| C / C++ | libFuzzer / AFL++ | Future work |

## 10. Research questions

- **RQ1** Does SAST-guided harness generation raise first-attempt harness success and detection
  rate vs. unguided generation?
- **RQ2** Does fusing SAST and fuzzing evidence reduce false positives vs. either alone?
- **RQ3 (spine)** Does the multi-agent design outperform a single agent with the same model and
  tools, at comparable cost?
- **RQ4** What does each module (scheduling, repair loop, fusion, patch validation) contribute?
- **RQ5** Do results generalize when Python is added, with minimal change to the components?
- **RQ6** In the cascade, what share of work do our models complete without the large model, how
  much cost and time does that save, and does detection stay comparable?

Metrics: harness success (first attempt and after repair), target-reachability, detection rate,
false-positive rate, fused-score precision, repair correctness, share of work done by our models,
cost saved, and time and tokens per commit. All prompts, model versions, and seeds are logged so
experiments can be repeated.

## 11. Term 1 — detailed objectives and status

**Goal:** a working single-agent vulnerability-confirmation tool on JS/TS, the shared
infrastructure it runs on, a reproducible benchmark, and the first numbers.

Implemented and tested end to end on real npm vulnerabilities:

- Docker fuzzing sandbox (Jazzer.js), no network, resource-limited.
- Diff parser and tree-sitter changed-function extraction for JS/TS and Python.
- Analyzer with Semgrep taint rules for five vulnerability classes (command injection, path
  traversal, code injection, prototype pollution, ReDoS).
- Fuzzer with 3× crash reproduction (only reproducible, class-matching crashes count).
- Orchestrator, CLI (`analyze`, `scan`, `benchmark-sast`), JSON and SARIF reports.
- GitHub Action that runs ProofHound on pull requests and uploads results to code scanning.
- Triage fusion score (rule-based SAST + fuzzing → confidence), the RQ2 core.
- Benchmark builder turning SecBench.js cases into two-commit repos with ground truth; a 31-case
  benchmark; training-data logging of every harness attempt; a pilot QLoRA notebook.

Remaining for Term 1: the single-agent LLM loop and its harness step (team-authored), the
single-agent runs on the benchmark, and the first RQ1/RQ2 numbers plus the pilot model.

## 12. Term 2 plan (weeks 15–28)

Term 2 completes the dynamic intelligence, builds the multi-agent system, runs the single-vs-multi
comparison, and adds the dashboard and auto-repair.

- **Full triage:** a standalone PoV script, LLM crash classification, and CVSS v3.1 — the
  confidence score stays rule-based and auditable.
- **Patcher (auto-repair):** minimal fix + regression test, accepted only on re-fuzzing + tests.
- **Multi-agent system and RQ3 comparison:** the specialized agents and orchestrator vs. the
  single agent on the same cases and budgets.
- **Cascade and our own models:** LoRA adapters per agent trained on verified distillation data;
  large-model escalation only on failure or low confidence (RQ6).
- **Continuous fuzzing and scheduling:** the corpus persists across commits.
- **Self-hosted dashboard:** per-project view of confirmed and fixed vulnerabilities, data kept in
  the organization.
- **Python fuzzing (Atheris)** and the Python benchmark (RQ5); optional CodeQL comparison and Go.
- **Research evaluation and paper:** all configurations and ablations for RQ1–RQ6, threats to
  validity, and a paper draft.

### Timeline

| Phase | Weeks | Work | Deliverable |
|---|---|---|---|
| T2-A Intelligence | 15–19 | Scheduler; full triage (PoV + CVSS); Patcher with regression tests; continuous fuzzing | Dynamic intelligence complete |
| T2-A2 Multi-agent & models | 17–21 | Specialized agents + orchestrator; train adapters on Colab; wire the cascade | Multi-agent system in the cascade |
| T2-B Dashboard & languages | 20–23 | Self-hosted dashboard; Python fuzzing (Atheris); Go/CodeQL if time | Dashboard; second fuzzed language |
| T2-C Evaluation | 23–26 | Full benchmark; single vs. multi (RQ3); all ablations; cascade vs. large-model-only | Results and figures |
| T2-D Writing | 27–28 | Paper, final report, defense demo | Paper draft; final thesis |

If time is short, Go and CodeQL are dropped first, then the Analyzer filter; the single/multi
comparison, the Patcher, the benchmark, and the evaluation are protected.

## 13. Team roles (5 members)

| Member | Term 1 | Term 2 |
|---|---|---|
| 1 — Agent / LLM | Single-agent loop and harness step; run on the benchmark | Multi-agent orchestration; cascade and escalation; RQ1/RQ3 |
| 2 — SAST / Analyzer | More Semgrep rule classes; false-positive analysis | Python analysis; optional CodeQL comparison |
| 3 — Fuzzing / Sandbox | Fuzzer, sandbox, benchmark construction | Full triage (PoV + CVSS); continuous fuzzing |
| 4 — Infra / Integration | SARIF, CLI, CI/GitHub Action | Patcher (auto-repair); self-hosted dashboard; Python fuzzing |
| 5 — ML / Research | Literature review; base-model selection; training data | Train LoRA adapters; RQ6; paper writing |

## 14. Deliverables and risks

**Deliverables:** an open-source tool (CLI and CI integration), a self-hosted dashboard, our
fine-tuned agent models and their training datasets, a benchmark with ground truth, a research-paper
draft, and the graduation report.

**Risks and mitigations:** harness and repair generation are the hardest parts — start with simple
pure functions and widen; fuzzing is slow — fixed time budgets and corpus reuse; our models may
handle little of the work or Colab may limit training — the large model covers every failure so
results stay correct, and we report the share honestly; scope growth — a fixed protected core with
extensions ordered by priority.
