# ProofHound — Deployment & Demo

Two things live here:
1. **Demo server** — rent a GPU, serve the model, tear it down. For the thesis defense / live demo.
2. **GitHub Action** — publish ProofHound as a tool that scans every push/PR (see `.github/`).

The model is the only part that needs a GPU. Everything else (SAST, Docker fuzzing) runs on an
ordinary machine / CI runner. The model is served over an HTTP endpoint and reached through an SSH
tunnel, so `local-harness` in `configs/default.yaml` (which points at `127.0.0.1:8000`) needs no change.

---

## 1. Demo server (rent → serve → destroy)

**Prerequisites (one-time):**
- `VAST_API_KEY` in `.env`
- SSH key at `~/.ssh/vast_proofhound` (+ its `.pub` registered on vast.ai)
- `pip install vastai` in the venv
- The v8 adapter at `models/harness-adapter-14b-v8/` (download once from Kaggle:
  `kaggle kernels output ebbrewqvqv/proofhound-harness-14b-v5 -p models/`)
- Docker running locally (for the fuzzing side)

**Rent and serve (one command):**
```bash
python deploy/demo_server.py up
```
This rents the cheapest viable 24 GB GPU, uploads the adapter, installs the serving deps, starts the
model in a tmux session, waits for `model ready`, and prints the SSH tunnel command. First launch
takes ~8–12 min (the base model downloads ~10 GB on the box).

**Open the tunnel** (keep it running in its own terminal — copy the printed command):
```bash
ssh -i ~/.ssh/vast_proofhound -p <PORT> -N -L 8000:127.0.0.1:8000 root@<HOST>
```

**Run a scan** against the served model (Docker fuzzing stays local):
```bash
python -m proofhound.evaluation.compare \
    --models local-harness --cases benchmark/cases \
    --out runs/demo --ground-truth-only --max-cases 3
```

**Tear it down when done (stops billing):**
```bash
python deploy/demo_server.py down
```

**Other commands:**
```bash
python deploy/demo_server.py status   # show the current box
python deploy/demo_server.py tunnel   # reprint the tunnel command
```

> Cost: the box bills ~$0.13–0.20/hr only while it is up. Always run `down` after the demo —
> `status` / `down` also list any stray instances so nothing is left running.

Manual fallback (if `demo_server.py up` hiccups) — the pieces it automates:
```bash
python scripts/vast_ctl.py offers            # pick an offer id
python scripts/vast_ctl.py rent <offer_id>   # -> instance id
python scripts/vast_ctl.py ssh <instance_id> # -> host/port
# scp the adapter to root@host:/root/adapter/ and serve_box_setup.sh to /root/, then:
ssh ... root@host "bash /root/serve_box_setup.sh"
python scripts/vast_ctl.py destroy <instance_id>
```

---

## 2. Publish as a GitHub Action

See `.github/workflows/proofhound.yml` (a ready-to-copy workflow) and `action.yml`. The flow:

```
PR / push → GitHub runner (has Docker)
          → ProofHound analyzes the diff (changed functions only)
          → SAST finds candidates → model writes harnesses → fuzz in Docker
          → confirmed vulns uploaded as SARIF → GitHub Security tab + PR annotations
```

The runner reaches the model over `MODEL_ENDPOINT` (a repo secret pointing at the served model,
e.g. an SSH-tunnelled vast.ai box or an HF Inference Endpoint). For the defense, point it at the
demo server above; for real use, a scale-to-zero endpoint is cheaper for intermittent scans.
