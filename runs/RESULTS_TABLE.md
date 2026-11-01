# ProofHound — Final Results

## 1. Headline: local fine-tuned model vs frontier models (ground-truth CVEs)

All models evaluated on the **same 27 benchmark ground-truth vulnerabilities**, under
**identical conditions** (same prompt, same Docker fuzzing environment, same flags:
`--ground-truth-only --class-seeds --rejection-sampling --call-chain-v2`, same temperature
sweep [0.1, 0.3, 0.5, 0.7, 0.9]). Verified prompt byte-identical across runs; finding sets
identical (diff=0).

| Model | Confirmed | Reached | Loaded | Type |
|---|---|---|---|---|
| **ProofHound 14B v8 (ours)** | **17/27 = 63%** | 78% | 85% | fine-tuned local (Qwen2.5-Coder-14B + LoRA) |
| GPT-6 | 10/27 = 37% | 56% | 67% | frontier |
| Gemini 3.8 Flash | 10/27 = 37% | 44% | 48% | frontier |
| Kimi K3 | 10/27 = 37% | 56% | 59% | frontier |
| DeepSeek V4 Pro | 6/27 = 22% | 33% | 41% | frontier |
| 7B v4 (our baseline) | 3.7% | 15% | 72% | earlier local model |

> The specialized local 14B model confirms **~1.7x more** vulnerabilities than the best
> general-purpose frontier model (63% vs 37%), at near-zero inference cost and fully on-prem.

## 2. Fairness controls (verified from the run data, not asserted)

| Dimension | Status |
|---|---|
| Number of cases/findings | 27 for every model (identical) |
| Finding set | byte-identical (case, finding_id); diff = 0 |
| Prompt | byte-identical per finding across all models |
| Fuzzing environment | same local Docker (`proofhound/jazzerjs`) |
| Flags | identical for all runs |
| Temperature sweep | [0.1, 0.3, 0.5, 0.7, 0.9] for all |
| max_tokens | ours 1536 vs frontier 16000 — the one difference, and it **favors frontier** (more room to reason), so our win is conservative |

## 3. ProofHound v8 — pipeline stages (27 cases)

| Stage | Count | % |
|---|---|---|
| Syntax OK | 27/27 | 100% |
| Loaded | 23/27 | 85% |
| Reached | 21/27 | 78% |
| **Confirmed** | **17/27** | **63%** |
| Errors | 0 | 0% |

By class: command-injection 15/23, path-traversal 2/4.

## 4. The measurement correction (why the number is trustworthy)

| Evaluation target | v8 Confirmed | What it measures |
|---|---|---|
| Full SAST finding set | 6/16 (38%) | includes ~9 false positives (`.split()`, linear regex) |
| **Benchmark ground truth** | **17/27 (63%)** | the real, exploit-verified CVE per case |

The earlier "38% wall" was an artifact of scoring against Semgrep's over-approximate findings.
Scoring against each case's authoritative `ground_truth` (one real CVE per case, each with a
reference exploit test) removes that noise. The benchmark ground truth is 27 command-injection +
4 path-traversal; zero redos / prototype-pollution (those were all SAST false positives).

## 5. Model progression

| Version | Base | Data | Confirmed |
|---|---|---|---|
| 7B v4 | Qwen2.5-Coder-7B | 108 ex (v3 prompts) | 3.7% |
| 14B v6 | Qwen2.5-Coder-14B | 107 ex (clean, pipeline prompts) | 31% (16-finding set) |
| 14B v8 | Qwen2.5-Coder-14B | 173 ex | **63% (ground truth)** |

## Notes
- 27 of 31 benchmark cases evaluated; 4 skipped (ground_truth sink matched no SAST finding) — same
  4 skipped for every model, so the comparison stays like-for-like.
- v8 served on a cloud Q RTX 6000 via SSH tunnel (fuzzing stayed local in Docker), box destroyed
  after. Frontier models served via the apinex.bond gateway (free tier). Serving location affects
  only speed, not output.
- Direct Claude comparison was blocked by API-provider billing/outage (CodeCraft down >24h; apinex
  Claude models require a paid top-up). The free frontier models above stand in as the frontier
  reference; a Claude ground-truth run remains available once a provider is funded.
- Artifacts: `runs/groundtruth-final-v8/`, `runs/gt-{deepseek,gpt6,gemini,kimi}/`.
