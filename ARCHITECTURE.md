# ProofHound — System Architecture

ProofHound takes a code change, finds candidate vulnerabilities, and **proves** which ones are
really exploitable by generating a fuzzing harness and crashing the code. It outputs confirmed
vulnerabilities (with a proof-of-crash), separating true bugs from SAST false positives.

```
                         ┌───────────────────────────────────────────────────────────┐
                         │                        ProofHound                          │
                         │                                                            │
   a commit / PR  ──────▶│  1. Analyzer      2. Harness agent     3. Fuzzer           │──▶  report.sarif
   (changed code)        │   (Semgrep SAST)   (LLM writes a         (Jazzer.js in       │     report.json
                         │        │           Jazzer.js harness)    Docker)             │     (confirmed
                         │        ▼                │                    │               │      vulns + PoC)
                         │   findings in      ┌────▼─────┐         ┌─────▼──────┐        │
                         │   changed funcs ──▶│  model   │────────▶│  harness   │        │
                         │                    │ endpoint │ harness │  + crafted │        │
                         │                    └──────────┘  code   │  input →   │        │
                         │                      (GPU)              │  crash?    │        │
                         │                                         └─────┬──────┘        │
                         │                        confirmed = a matching ▼ bug detector  │
                         │                        fired (CommandInjection / PathTraversal │
                         │                        / PrototypePollution / ReDoS)          │
                         └───────────────────────────────────────────────────────────┘
```

## The pipeline (one finding at a time)

1. **Analyzer** — `core/analysis/` (Semgrep via `core/analysis/semgrep.py`).
   Runs SAST over the functions changed in the commit, producing `Finding`s (rule, class, sink
   location). Only *changed* functions are analyzed, so a PR scan is fast.

2. **Harness agent** — `core/harness/` (`agent.py`, `build_prompt`, `core/analysis/call_chain.py`).
   For each finding it builds a prompt — the vulnerable function, the sink line, and a tree-sitter
   call chain from an exported API down to the sink — and asks the model for a Jazzer.js harness.
   It validates syntax, loads the harness in the sandbox, and repairs on failure (or samples several
   temperatures with `produce_with_sampling`).

3. **Fuzzer** — `core/fuzzing/` (`fuzzer.py`, `sandbox.py`) + `docker/jazzerjs/`.
   Runs the harness under Jazzer.js inside a locked-down Docker sandbox (`--network none`, read-only
   target, memory/CPU/pid limits), seeded with class-specific inputs from `data/seeds/`. A finding is
   **confirmed** only when a bug detector whose kind matches the finding's class fires and the crash
   replays.

4. **Reporting** — `core/reporting/sarif.py`.
   Emits `report.json` and `report.sarif`. SARIF uploads into GitHub code scanning (Security tab +
   inline PR annotations).

The **model** is the only GPU component. It is served over an OpenAI-compatible HTTP endpoint
(`training/serve/serve_local.py`), reached via `MODEL_ENDPOINT` (or `127.0.0.1:8000` through an SSH
tunnel). Everything else — SAST and Docker fuzzing — runs on an ordinary machine or CI runner.

## Two run modes (`proofhound scan --agent ...`)

- **single** — one LLM drives every tool through a step loop (`single_agent/`).
- **multi** — the specialized pipeline above, one stage per component (`multi_agent/`). This is what
  the GitHub Action and the evaluations use.

## Repository layout

```
src/proofhound/
  cli.py                  `proofhound scan` entry point
  core/
    analysis/             SAST (Semgrep) + tree-sitter call-chain extraction
    harness/              prompt building, the harness agent, syntax/load checks
    fuzzing/              Docker sandbox + Jazzer.js fuzzer + class-aware seeds
    adapters/             language adapter (JavaScript/TypeScript)
    llm/                  OpenAI-compatible client (local endpoint / gateways)
    reporting/            SARIF + JSON reports
    datalog/              attempt logging
  single_agent/ multi_agent/   the two run modes
  evaluation/             compare.py — benchmark evaluation + --ground-truth-only

benchmark/cases/          held-out eval set (one ground_truth CVE per case + exploit test)
training/                 data builders, the model fine-tuning notebooks, the inference server
data/seeds/               class-aware fuzzer seed corpora
docker/jazzerjs/          the fuzzing sandbox image
rules/semgrep/            the SAST rules
deploy/                   on-demand GPU demo server + GitHub Action (see deploy/README.md)
configs/default.yaml      models, budgets, sandbox limits
```

## The model

`Qwen2.5-Coder-14B-Instruct` + a LoRA adapter, fine-tuned on Claude/Gemini-distilled confirmed
harnesses (clean train/eval split, pipeline-format prompts). On the benchmark's ground-truth CVEs
it confirms **63%** — well above the 7B baseline (3.7%) and the frontier models tested through the
same pipeline (22–37%). See `runs/RESULTS_TABLE.md`.

## Deployment

- **Demo / defense:** `deploy/demo_server.py up` rents a GPU, serves the model, prints the tunnel;
  `down` destroys it. Pay only for the minutes of the demo. See `deploy/README.md`.
- **Production / CI:** copy `.github/workflows/proofhound.yml` into a repo and set `MODEL_ENDPOINT`
  to a served model (a scale-to-zero HF Inference Endpoint is cheapest for intermittent scans).
```
PR / push → GitHub runner (Docker) → analyze diff → harnesses (model endpoint) → fuzz → SARIF
```
