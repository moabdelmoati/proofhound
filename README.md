# ProofHound

Agentic vulnerability discovery and repair. SAST findings on changed code guide an LLM to write
fuzz harnesses; a coverage-guided fuzzer confirms the bug in a sandbox; triage fuses both signals
into one confidence score, produces a proof-of-vulnerability (PoV), and a patch is accepted only if
re-fuzzing confirms the fix.

**Research spine:** the project compares a **single agent** (Term 1) against a **multi-agent**
system (Term 2) with the same model, tools, and infrastructure (RQ3). See
[docs/shared/proposal.md](docs/shared/proposal.md) and the full
[docs/shared/architecture.md](docs/shared/architecture.md) (Arabic: `docs/shared/proposal.ar.md`,
`docs/shared/architecture.ar.md`).

## Layout

The code is split by architecture. Both terms build on one shared `core`; Term 1 adds the single
agent, Term 2 the multi-agent pipeline, so neither copies the other.

| Path | Contents |
|---|---|
| `src/proofhound/core/` | Shared by both terms: models, config, budget, LLM clients, attempt log |
| `src/proofhound/core/adapters/` | Per-language adapters (JavaScript/TypeScript, Python) |
| `src/proofhound/core/analysis/` | Diff → changed functions, SAST (Semgrep), the Analyzer |
| `src/proofhound/core/fuzzing/` | Docker sandbox and the Fuzzer (crash confirmation and replay) |
| `src/proofhound/core/harness/` | Harness generation with execution checks; the local model's chat format |
| `src/proofhound/core/reporting/` | JSON and SARIF reports |
| `src/proofhound/single_agent/` | **Term 1** — one LLM drives the tools in a single loop |
| `src/proofhound/multi_agent/` | **Term 2** — specialized agents in a pipeline (triage, scheduler, patcher, cascade) |
| `src/proofhound/evaluation/` | Benchmark case builder, SAST scoring, model comparison |
| `training/generate/` | Training-data generation (distillation, OSS-Fuzz seed) |
| `training/train/` | QLoRA fine-tuning, locally or on Colab |
| `training/serve/` | Serve the fine-tuned model behind an OpenAI-compatible endpoint |
| `tests/` | Mirrors `src/proofhound/` (`core/`, `single_agent/`, `multi_agent/`) |
| `docs/shared/` · `docs/term1/` · `docs/term2/` | Proposal and architecture · Term 1 docs · Term 2 docs |
| `docker/` · `rules/semgrep/` · `configs/` | Sandbox images · our Semgrep rules · settings |
| `benchmark/` · `experiments/` | Benchmark cases with ground truth · experiment results |

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows; use .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
cp .env.example .env
docker build -t proofhound/jazzerjs:latest docker/jazzerjs
docker pull semgrep/semgrep:latest
proofhound --help
```

## Usage

```bash
# SAST findings on the functions a commit changed
proofhound analyze --repo <repo> --commit <sha>

# Full pipeline with an LLM-generated, execution-checked harness
proofhound scan --repo benchmark/cases/command-exists_1.2.2/repo

# Score SAST alone against every benchmark case's ground-truth sink
proofhound benchmark-sast
```

Benchmark cases are built from SecBench.js (clone it into `vendor/SecBench.js`) with
`proofhound.evaluation.secbench.build_case`; each case's `case.yaml` is committed, its `repo/`
is rebuilt locally.

`proofhound scan` uses the model selected by `harness.model` in `configs/default.yaml`. Set its
provider credentials in the environment, then run without a `--harness-dir`; every generated
harness attempt is appended to `training/data/harness_attempts.jsonl`.
