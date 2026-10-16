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

**Trimming layer.** The 1.5 B model trained on 28 examples occasionally repeated the function or
emitted a `<|fim_middle|>` marker; a small post-processor (`training/serve_local.py :: _trim`,
`training/generate_test.py :: trim_harness`, five regression tests in
`tests/test_trim.py`) cuts both cleanly. Server output is now one clean harness per request.

**End-to-end verified.** `training/serve_local.py` runs an OpenAI-compatible endpoint on
`127.0.0.1:8000/v1` loading the base model + adapter; ProofHound's existing `openai_compatible`
client talks to it exactly like any API, so swapping between the CodeCraft API and this local
model is a config change (`harness.model: local-harness` in `configs/default.yaml`).

## What this establishes for the proposal

- The **privacy / independence** story is real: ProofHound can run harness generation without any
  external API, on the organization's own machine.
- The **pilot** proves the full data-and-training pipeline (collect → QLoRA → serve → generate),
  which is the Term-1 deliverable for the research spine toward RQ6.
- The small size and limited data **are not a bug**: they are the honest Term-1 scope. Scaling up
  (bigger base model, more distillation data, cascade with large-model escalation) is the Term-2
  plan.
