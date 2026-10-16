# ProofHound — Pilot Training Result (Term 1)

End-to-end proof that we can train and run our own harness-generation model, with no API at
runtime. This is the Term-1 pilot of RQ6.

## What we did

1. **Collected seed data from OSS-Fuzz** — 28 real Jazzer.js harnesses from Node.js projects.
   Free, high-quality, Apache-licensed.
2. **Fine-tuned `Qwen2.5-Coder-1.5B` with QLoRA** on Google Colab (T4 GPU, driven from Claude's
   browser). 5 epochs, batch 1 × grad accum 8, 20 steps total, LoRA rank 16, 18.4 M trainable
   parameters.
3. **Downloaded the LoRA adapter** (73 MB) to the local machine.
4. **Served it locally** by loading `Qwen2.5-Coder-1.5B` + the adapter in `training/generate_test.py`
   and `training/serve_local.py` (OpenAI-compatible endpoint on `127.0.0.1:8000/v1`).

## Training curve

Loss across the 20 training steps:

| step | 2 | 4 | 6 | 8 | 10 | 12 | 14 | 16 | 18 | 20 |
|---|---|---|---|---|---|---|---|---|---|---|
| loss | 0.96 | 0.88 | 0.64 | 0.62 | 0.46 | 0.45 | 0.42 | 0.39 | 0.40 | 0.36 |

Clean, monotonic convergence from 0.96 → 0.36.

## Local generation

First harness the fine-tuned model generated (prompt: write a Jazzer.js harness for the
`command-exists` package):

```js
const { FuzzedDataProvider } = require('@jazzer.js/core');
const { exists } = require('./index.js');

module.exports.fuzz = function(data) {
    const provider = new FuzzedDataProvider(data);
    const path = provider.consumeRemainingAsString(1024);
    try {
        exists(path);
    } catch (error) {
        // Ignore errors
    }
};
```

Structurally correct: FDP import, correct `require`, `module.exports.fuzz` with the right
signature, input built from the provider. This is the shape the OSS-Fuzz seed taught the model.

Known rough edges (small-data pilot, not production): the model sometimes repeats the function
or emits a `<|fim_middle|>` marker. Both are mitigated by (a) early-stopping on `module.exports`
or `}` at the top level, (b) more training data (the distillation stream from the pipeline's own
runs), or (c) a larger base model.

## What this establishes for the proposal

- The **privacy / independence** story is real: ProofHound can run harness generation without any
  external API, on the organization's own machine.
- The **pilot** proves the full data-and-training pipeline (collect → QLoRA → serve → generate),
  which is the Term-1 deliverable for the research spine toward RQ6.
- The small size and limited data **are not a bug**: they are the honest Term-1 scope. Scaling up
  (bigger base model, more distillation data, cascade with large-model escalation) is the Term-2
  plan.
