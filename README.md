# ProofHound

Agentic vulnerability discovery and repair. SAST findings on changed code guide an LLM to write
fuzz harnesses; a coverage-guided fuzzer confirms the bug in a sandbox; triage fuses both signals
into one confidence score, produces a proof-of-vulnerability (PoV), and a patch is accepted only if
re-fuzzing confirms the fix.

## Layout

| Path | Contents |
|---|---|
| `src/proofhound/agents/` | Analyzer, Scheduler, Harness, Fuzzer, Triage, Patcher |
| `src/proofhound/orchestrator/` | Pipeline state, retries, time/token budgets |
| `src/proofhound/llm/` | LLM clients and the small-model → large-model cascade |
| `src/proofhound/sast/` | SAST engine interface (Semgrep first) |
| `src/proofhound/adapters/` | Per-language adapters (JS/TS first, Python in Term 2) |
| `src/proofhound/sandbox/` | Docker runner: no network, resource limits |
| `src/proofhound/vcs/` | Diff parsing and changed-function extraction |
| `src/proofhound/reporting/` | JSON, SARIF, MR comment output |
| `src/proofhound/datalog/` | Logs verified harnesses/patches as training data |
| `docker/` | Sandbox images (Jazzer.js) |
| `rules/semgrep/` | Our Semgrep rules |
| `benchmark/` | Benchmark cases (SecBench.js, advisories) with ground truth |
| `training/` | Colab notebooks and datasets for QLoRA adapters |
| `experiments/` | Experiment configs and results (RQ1–RQ6) |
| `examples/` | Demo targets (NodeGoat, Juice Shop, injected cases) |
| `docs/` | Architecture notes and literature review |

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows; use .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
cp .env.example .env
proofhound --help
```
