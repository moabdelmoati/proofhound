#!/bin/bash
# One-shot setup for serving the ProofHound harness model on a fresh vast.ai GPU box.
# Run this ON the box (after the adapter has been copied to /root/adapter).
#
#   bash serve_box_setup.sh
#
# It clones the repo, installs the serving deps, fixes a tokenizer incompatibility,
# and starts serve_local.py in a detached tmux session named "serve" on port 8000.
# Tail /root/serve.log and wait for "model ready" before opening the SSH tunnel.
set -e

REPO_URL="https://github.com/moabdelmoati/proofhound.git"
BRANCH="distill/v4-cloud"
BASE="unsloth/Qwen2.5-Coder-14B-Instruct-bnb-4bit"
ADAPTER="/root/adapter"

echo "[1/5] cloning repo ($BRANCH)..."
cd /root
[ -d proofhound ] || git clone -q --depth 1 -b "$BRANCH" "$REPO_URL"
cd /root/proofhound

echo "[2/5] installing serving deps..."
pip install -q "transformers==4.47.1" peft bitsandbytes accelerate pydantic protobuf sentencepiece \
  tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-python 2>&1 | tail -1 || true
pip install -q -e . --no-deps 2>&1 | tail -1 || true

echo "[3/5] fixing adapter tokenizer_config (transformers rejects list extra_special_tokens)..."
python - <<'PY'
import json, pathlib
p = pathlib.Path("/root/adapter/tokenizer_config.json")
if p.exists():
    d = json.loads(p.read_text())
    if isinstance(d.get("extra_special_tokens"), list):
        d.pop("extra_special_tokens"); p.write_text(json.dumps(d)); print("  fixed")
    else:
        print("  ok")
PY

echo "[4/5] starting serve in tmux session 'serve'..."
cat > /root/run_serve.sh <<EOF
#!/bin/bash
cd /root/proofhound
export PYTHONPATH=/root/proofhound/src
export HF_HUB_ENABLE_HF_TRANSFER=0
exec python training/serve/serve_local.py \\
  --adapter $ADAPTER --base $BASE --device cuda --load-4bit --port 8000
EOF
chmod +x /root/run_serve.sh
tmux kill-session -t serve 2>/dev/null || true
tmux new-session -d -s serve 'bash /root/run_serve.sh > /root/serve.log 2>&1'

echo "[5/5] launched. The base model (~10GB) downloads on first load."
echo "  Watch:  tail -f /root/serve.log   (wait for: model ready)"
echo "  Check:  curl http://127.0.0.1:8000/v1/models"
