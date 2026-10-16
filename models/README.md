# how the trained adapter was produced (Term 1 pilot)
models/harness-adapter/ is a LoRA adapter for Qwen2.5-Coder-1.5B, trained on OSS-Fuzz seed
harnesses on a Colab T4 (loss 0.96 -> 0.36 over 5 epochs). Regenerate with training/train_local.py
(local GPU) or the one-cell Colab recipe. Serve it with training/serve_local.py.
