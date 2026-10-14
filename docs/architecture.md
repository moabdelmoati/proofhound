# ProofHound — Architecture

Full technical architecture of the project across both terms. This document is the single source
of truth for how the system is put together; the proposal (`proposal.md`) covers the research
framing and plan.

---

## 1. Goal and principle

ProofHound confirms and repairs security vulnerabilities in the code a commit changes. Its guiding
principle is **execution as the judge**: nothing is reported as a vulnerability unless a sandboxed
run reproduced it, and no fix is accepted unless a re-run shows the vulnerability is gone. SAST and
the LLM propose; execution decides.

Two front-ends sit over one shared core:

- **Single agent (Term 1)** — one LLM in a tool-use loop does the whole job.
- **Multi-agent (Term 2)** — specialized agents, each with a fixed role, coordinated by an
  orchestrator, with our own small models in a cascade under a large model.

The single-vs-multi comparison (RQ3) is the backbone of the research.

## 2. High-level flow

```
commit ──▶ Diff parser ──▶ Language adapter ──▶ Analyzer (SAST)
                                                   │  findings on changed functions, by severity
                                                   ▼
                                   ┌──────── per finding ────────┐
                                   │  Harness  ──▶  Fuzzer        │
                                   │   (LLM + repair loop)        │
                                   │        │ working harness     │
                                   │        ▼                     │
                                   │  sandbox fuzz ──▶ crash?     │
                                   │        │ reproduce 3×        │
                                   │        ▼                     │
                                   │  Triage: fuse SAST+fuzzing   │
                                   │   → confidence, PoV, CVSS    │
                                   │        │ confirmed            │
                                   │        ▼                     │
                                   │  Patcher: fix + regression   │
                                   │   accept iff PoV gone & tests│
                                   └──────────────┬───────────────┘
                                                  ▼
                        Reports: JSON · SARIF · MR comment · Dashboard
```

The **Orchestrator** drives this sequence, owns the time/token **Budget**, and writes every
artifact to `runs/<commit>/`. In Term 1 the single agent performs the inner box as one LLM loop; in
Term 2 each box is a separate agent.

## 3. Components

### 3.1 Diff parser — `vcs/diff.py`
`git diff -U0 <commit>^ <commit>` → `{file: set[changed_line]}` for the active language's
extensions. Added/modified lines only; deletions ignored (only code that exists after the commit
can be fuzzed). The empty-tree hash lets the first commit of a repo be diffed like any other.

### 3.2 Language adapter — `adapters/`
One class per language behind `LanguageAdapter`; a registry (`get_adapter`) selects by name.
Responsibilities: extract changed functions (tree-sitter), give a harness template, build the
fuzz / replay / coverage commands, read coverage, and parse the fuzzer's reports.
- **JavaScript/TypeScript** (`javascript.py`, Jazzer.js): one grammar set serves JS and TS; a
  cursor walk avoids a tree-sitter crash on large files (pinned `< 0.26`).
- **Python** (`python.py`, Atheris): analysis side implemented; fuzzing hooks land in Term 2.
Adding a language is one adapter and a rules directory — no agent changes.

### 3.3 Analyzer — `agents/analyzer.py`
Runs the SAST engine on the changed files, keeps only findings inside a changed function, and
orders them by severity. Each `Finding` carries rule id, severity, message, source parameter, sink
expression, vulnerability class, and the enclosing `ChangedFunction`.

### 3.4 SAST engine — `sast/`
`SastEngine` interface; `SemgrepEngine` runs Semgrep in Docker (`--network none`) and converts its
JSON into `Finding`s. Our taint rules live in `rules/semgrep/<language>/`: the source is a function
parameter (library code) or request data (app code); the sink is the dangerous operation. Five JS
classes today: command injection, path traversal, code injection, prototype pollution, ReDoS; two
Python classes (command injection, path traversal). Rules embed `[source][sink]` markers so the
finding names the tainted parameter. The engine is pluggable — our own engine, or CodeQL for
comparison, can replace it.

### 3.5 Harness agent / step — `agents/harness.py`, `orchestrator/manual_harness.py`
Given the function, its export path, the finding, and a template, an LLM writes a `harness.js`. A
repair loop feeds each failure back to the model through a validation ladder — syntax → load →
target reached (coverage) → coverage growth — up to a configured number of attempts, then the
finding is `harness_failed`. `ManualHarnessStep` supplies hand-written harnesses for LLM-free runs
(testing and the demo fallback). Every attempt is logged for training (§3.11). The LLM prompt is
authored by the team.

### 3.6 Fuzzer agent — `agents/fuzzer.py`
Runs the fuzzer in the sandbox for the configured budget with the bug detector for the finding's
class enabled, maintains a per-target corpus on disk, and parses the output for security
bug-detector reports. Each candidate crash is **replayed 3×**; only crashes that reproduce every
time and whose stack trace reaches the target code become confirmed `Crash`es.

### 3.7 Triage — `agents/triage.py`
Fuses the static and dynamic signals into one confidence in [0, 1]. Rule-based and auditable: a
reproduced, class-matching crash → ≥ 0.90; a clean fuzzing run lowers the SAST prior (more the
longer it ran); a class mismatch is mid-range; no harness leaves the SAST-only prior. Term 2 adds a
standalone PoV script, LLM crash classification, and a CVSS estimate — these refine explanatory
fields only, never the score.

### 3.8 Patcher (auto-repair) — Term 2
For each confirmed finding, proposes a minimal edit to the vulnerable function and a regression
test. Applies it on a scratch copy, then **re-runs the PoV and the project's existing tests**; the
patch is accepted only if the PoV no longer triggers and all tests still pass. The vulnerable
application code is never modified in place until a patch is accepted. LLM-authored, execution-gated.

### 3.9 Scheduler — Term 2
Rule-based: orders targets by severity and assigns each a fuzzing-time slice within the run budget;
reuses the stored corpus so later commits start from earlier coverage (continuous fuzzing).

### 3.10 Sandbox — `sandbox/docker_runner.py`
Every generated artifact runs in a fresh container: `--network none`, memory/CPU/pids limits,
`--read-only` root with a tmpfs workdir, non-root user, host-enforced timeout. The target is
mounted read-only at `/work/target`; a writable `/work/out` holds the harness, corpus, and crash
files. Dependencies are installed once, beforehand, in a separate networked container; the fuzzing
container never has network.

### 3.11 Orchestrator and budget — `orchestrator/`
Runs the flow per finding, enforces a wall-clock + token `Budget` (skips remaining findings when
exhausted), isolates failures (one failing finding never aborts the run), and writes
`runs/<commit>/`. The harness step is any object with `produce(finding, target, out) -> Harness`,
so the single agent, the multi-agent harness, or the manual step all plug in identically.

### 3.12 Training-data logger — `datalog/logger.py`
Appends one JSON line per harness attempt (prompt, output, per-stage check results, tokens, model).
Attempts from benchmark `eval` cases are tagged and excluded from training (no leakage). Verified
attempts are the distillation set for the pilot and full adapters.

### 3.13 Reporting — `reporting/`
- **JSON** (`report.json`): the full run — findings, statuses, crashes, confidence, timings, tokens.
- **SARIF** (`report.sarif`): SARIF 2.1.0 for GitHub/GitLab code scanning; confirmed findings carry
  `security-severity` so they surface inline on a PR.
- **MR comment** (Term 2) and the **dashboard** (§5) read the same JSON.

## 4. Single agent vs. multi-agent

| | Single agent (Term 1) | Multi-agent (Term 2) |
|---|---|---|
| Control | one LLM loop | orchestrator + specialized agents |
| Tools | read file, run SAST, write harness, run fuzzer, propose fix | each agent owns its tools |
| Models | one model | per-agent small models in a cascade under a large model |
| Shared | sandbox, SAST, fuzzer, benchmark, reports, dashboard | same |

RQ3 compares them on identical cases and budgets, measuring detection, false-positive rate, repair
correctness, and cost.

## 5. Self-hosted dashboard — Term 2

A web dashboard deployed inside the organization. It reads the `runs/` JSON (and a small local
database) and shows, per scanned project (web apps and services):

- confirmed vulnerabilities with severity, PoV, and the reproducing input;
- which findings have an accepted fix and which are still open;
- history across commits.

**Privacy by design.** The dashboard, the pipeline, the sandbox, and the database all run on the
organization's own machines. Source code, findings, and PoVs never leave its network. The only
outbound call is the optional large-model API, which can be replaced by a self-hosted model so the
deployment is fully offline. No telemetry.

## 6. Security model

- Observed content (source code, SAST messages, dependency docs) is **data, never instructions** —
  it cannot change the agents' behavior.
- All generated code is untrusted and runs only in the sandbox (§3.10).
- Secrets (the large-model API key) are read from the environment, never logged, never sent to the
  sandbox.
- Downloaded packages are unpacked into isolated per-case directories.

## 7. Technology

| Need | Choice | Why |
|---|---|---|
| Orchestrator / agents | Python 3.11+ | Semgrep, Atheris, and training are all Python |
| Parsing | tree-sitter (JS/TS, Python) | one approach per language |
| SAST | Semgrep in Docker (taint mode) | pluggable; no native install |
| Fuzzer (JS/TS) | Jazzer.js | coverage-guided, security bug detectors |
| Fuzzer (Python) | Atheris | same model for a second language |
| Sandbox | Docker | network off, resource limits |
| LLM access | provider-agnostic client (Anthropic / OpenAI / OpenAI-compatible / local) | swap models per agent; self-hostable |
| CLI | Typer | `analyze`, `scan`, `benchmark-sast` |
| Models | open code base model + QLoRA LoRA adapters | cheap per-agent specialization on Colab |

## 8. Repository layout

```
src/proofhound/
  models.py          typed objects passed between components
  config.py, cli.py  settings and the command line
  vcs/               diff parsing
  adapters/          per-language: javascript, python, registry
  sast/              engine interface + Semgrep
  agents/            analyzer, scheduler, harness, fuzzer, triage, patcher
  orchestrator/      pipeline, budget, manual harness step
  llm/               provider-agnostic client, cascade
  sandbox/           Docker runner
  reporting/         json, sarif (dashboard in Term 2)
  datalog/           training-data logger
  benchmark/         SecBench.js case builder, SAST scorer
docker/jazzerjs/     sandbox image
rules/semgrep/       taint rules per language
benchmark/cases/     built cases (case.yaml committed, repo/ rebuilt locally)
training/            QLoRA notebooks and datasets
experiments/         results (RQ1–RQ6)
docs/                proposal and this architecture
```

## 9. Data contract

Every component reads and writes the typed objects in `models.py` only — `ChangedFunction`,
`Finding`, `Harness`, `Crash`, `TriageResult`, `Patch`, `FindingResult`, `RunReport` — so each can
be built and tested in isolation and the single/multi front-ends are interchangeable. `produced_by`
(small/large/none) is recorded on generated objects so RQ6 can be measured from day one.
