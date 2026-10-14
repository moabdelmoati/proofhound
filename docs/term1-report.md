# ProofHound — Term 1 Report

Status of the first term: the shared infrastructure, a working JS/TS pipeline, the benchmark, the
first results, and what remains.

---

## 1. What Term 1 set out to deliver

Per the (restructured) proposal, Term 1 delivers: the shared per-commit infrastructure, a working
**single-agent** vulnerability-confirmation tool on JS/TS, a reproducible benchmark, the first
RQ1/RQ2 numbers, and a pilot fine-tuned model. The research spine is **single-agent vs.
multi-agent** (RQ3), built across both terms.

## 2. What is implemented (and tested)

All of the following runs end to end and is covered by unit tests (19 passing) and a real-case
run on `command-exists@1.2.2`:

| Area | Module | State |
|---|---|---|
| Sandbox | `sandbox/docker_runner.py`, `docker/jazzerjs/` | Jazzer.js 4, no network, read-only root, CPU/mem/pids limits, host timeout |
| Diff | `vcs/diff.py` | `git diff -U0`, added lines, empty-tree first-commit |
| Adapters | `adapters/javascript.py`, `adapters/python.py`, registry | JS/TS + Python function extraction (tree-sitter) |
| SAST | `sast/semgrep.py`, `rules/semgrep/` | Semgrep in Docker; 5 JS classes, 2 Python classes |
| Analyzer | `agents/analyzer.py` | findings inside changed functions, by severity |
| Harness | `agents/harness.py`, `orchestrator/manual_harness.py` | LLM harness step (team prompt) + manual step for LLM-free runs |
| Fuzzer | `agents/fuzzer.py` | fuzz + 3× crash reproduction; corpus on disk |
| Triage | `agents/triage.py` | rule-based SAST+fuzzing fusion → confidence (RQ2 core) |
| Orchestrator | `orchestrator/pipeline.py`, `budget.py` | per-finding flow, time/token budget, failure isolation |
| Single agent | `baseline/tools.py`, `baseline/single_agent.py` | deterministic tools + dispatch loop (team prompt) |
| Reports | `reporting/json_report.py`, `reporting/sarif.py` | JSON + SARIF 2.1.0 |
| CI | `.github/workflows/proofhound.yml` | runs on PRs, uploads SARIF to code scanning |
| Data log | `datalog/logger.py` | every harness attempt → training JSONL, eval cases tagged |
| Benchmark | `benchmark/secbench.py`, `benchmark/runner.py` | SecBench.js → two-commit repos; SAST scorer |
| Training | `training/notebooks/pilot_harness_qlora.ipynb` | Colab QLoRA pilot |
| Docs | `docs/` | proposal + architecture (EN/AR), literature review, base-model selection |

Beyond the original Term-1 scope we also pulled forward: SARIF + GitHub Action, the Python
analysis side, the triage fusion score, three extra vulnerability classes, and a 31-case benchmark.

## 3. First results

**SAST alone on the benchmark** (31 scored cases, `experiments/results/sast.json`):

- **Detection: 30/31** cases — a finding lands on the ground-truth sink.
- **False positives: 244** total inside changed functions (~7.9 per case).

This is the RQ2 motivation in one number: SAST finds almost everything but drowns it in false
positives, so execution-based confirmation is needed before showing a developer anything.

**End-to-end confirmation** (demo case `command-exists@1.2.2`, manual harness):
the pipeline extracts 17 changed functions, SAST raises 4 command-injection findings, the fuzzer
confirms the true one at `lib/command-exists.js:78:22`, reproduced 3/3, fused confidence 0.90, and
writes `report.json` + `report.sarif`. Runtime ~20 s.

## 4. What remains for Term 1

| Item | Who / needs |
|---|---|
| Harness Agent prompt + single-agent prompt | **Team** (filter-sensitive; scaffolding is ready) |
| LLM provider wiring + API key (CodeCraft) | **User** — base URL, model ids, key in `.env` |
| Single-agent runs on the benchmark → RQ1/RQ2 numbers | after the two above |
| Pilot QLoRA training on Colab | after runs produce training data; **Colab** |
| Literature review final write-up for submission | drafted in `docs/literature-review.md`; team polishes |
| Term 1 slides + live demo | team |

## 5. How to reproduce

```bash
python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"
docker build -t proofhound/jazzerjs:latest docker/jazzerjs
docker pull semgrep/semgrep:latest
# clone SecBench.js into vendor/ and build cases with proofhound.benchmark.secbench.build_case
proofhound benchmark-sast                      # SAST results table
proofhound scan --repo benchmark/cases/command-exists_1.2.2/repo \
                --harness-dir benchmark/cases/command-exists_1.2.2/harnesses   # LLM-free demo
```

## 6. Honest notes for the defense

- We are **ahead of the week-3 plan** (which asked only for the literature review and scope); the
  build is at roughly week 8–9 of the plan.
- The **LLM-driving prompts are team-authored**; everything around them is built and tested.
- The real RQ1/RQ2 numbers need one API key; the benchmark, baselines, and reports are ready to
  produce them the moment the model is wired in.
- SecBench.js metadata is noisy; our builder documents and works around it (an honest threat to
  validity to report).
