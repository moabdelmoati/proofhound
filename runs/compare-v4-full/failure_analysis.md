# Failure Analysis — compare-v4-full (local-harness)

**Total findings:** 108  |  **Cases:** 12  |  **Attempts:** 293

## Category Breakdown

| Category | Count | % | Meaning |
|---|---|---|---|
| confirmed | 4 | 3.7% | crash reproduced — the model succeeded |
| reached_not_confirmed | 12 | 11.1% | sink reached but fuzzer could not crash it |
| loaded_not_reached | 62 | 57.4% | harness loads but can't drive execution to sink |
| env_blocked | 0 | 0.0% | sandbox lacks required binary/env |
| syntax_ok_not_loaded | 16 | 14.8% | parse-OK code but module/require errors |
| syntax_fail | 14 | 13.0% | model emitted invalid code |
| no_output | 0 | 0.0% | model produced no usable harness |

## By Vulnerability Class

| class | total | confirmed | reached_not_conf | loaded_not_reached | env_blocked | other |
|---|---|---|---|---|---|---|
| command-injection | 18 | 1 | 3 | 6 | 0 | 8 |
| path-traversal | 24 | 2 | 1 | 10 | 0 | 11 |
| prototype-pollution | 9 | 1 | 4 | 3 | 0 | 1 |
| redos | 57 | 0 | 4 | 43 | 0 | 10 |

## Distillation Targets (by priority)

Total targets (excluding confirmed + env_blocked): **104**

- **Priority 1** (loaded_not_reached — reach gap): 62
- **Priority 2** (reached_not_confirmed — confirm gap): 12
- **Priority 3** (other): 30

## Confirmed Findings (the baseline wins)

- `asset-cache_0.0.6` / path-traversal / `029e512bac`
- `asset-cache_0.0.6` / path-traversal / `a55ef60143`
- `blamer_0.1.13` / command-injection / `971e749caf`
- `buns_1.1.6` / prototype-pollution / `38c1722d51`

## Recommendations

1. **Primary bottleneck is reach** — 62 findings (57%) load but don't reach the sink. Distillation + call-chain v2 target this directly.
2. **Confirm gap is 12 findings** — these reach the sink but the fuzzer fails to craft a crashing input. Class-aware seeds target this directly.
3. **Environment losses: 0 findings** — document and exclude from distillation target set (fixing them is sandbox work, not model work).
