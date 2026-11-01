# ProofHound — Live Demo Runbook (thesis defense)

Goal: serve the fine-tuned 14B model on a rented GPU, run a real scan, and show a **CONFIRMED**
command-injection vulnerability proven by the model + fuzzing — live, in front of the committee.

Verified end-to-end on 2026-11-01: the case **`adb-driver_0.1.8`** confirms in ~45 seconds.

> Total cost: the GPU box bills ~$0.13–0.20/hr, only while it is up. A full demo session is ~$0.20.
> **Always run the teardown step at the end.**

---

## 0. One-time prerequisites (already set up on this machine)

- `VAST_API_KEY` in `.env`  ✅
- SSH key at `~/.ssh/vast_proofhound`  ✅
- `vastai` installed in `.venv`  ✅
- Adapter at `models/harness-adapter-14b-v8/`  ✅
- Docker Desktop installed + `proofhound/jazzerjs:latest` image built  ✅

If you move to another machine, redo these (see `deploy/README.md`).

---

## 1. Before the defense — start ~20 minutes early

The box takes ~8–12 min to download the base model and become ready. Do NOT rely on a cold start
in front of the committee. Rent early and keep it warm.

### 1a. Make sure Docker is running
Open Docker Desktop. Wait until the whale icon is steady (not animating). Verify:
```bash
docker info
```
If Docker Desktop crashes on start with a `docker-secrets-engine ... engine.sock` error, run this
once (PowerShell), then reopen Docker Desktop:
```powershell
Get-Process "*docker*" | Stop-Process -Force; wsl --shutdown; Remove-Item "$env:LOCALAPPDATA\docker-secrets-engine\engine.sock*" -Force
```

### 1b. Rent the GPU and serve the model
```bash
python deploy/demo_server.py up
```
Wait for it to print `model ready` and the SSH tunnel command. (If the terminal output gets lost,
check progress with `python deploy/demo_server.py status`, then read the box's log over SSH —
see Troubleshooting.)

### 1c. Open the SSH tunnel — keep this terminal open the whole time
Copy the exact command `up` printed (host and port change every rental). It looks like:
```bash
ssh -i ~/.ssh/vast_proofhound -p <PORT> -N -L 8000:127.0.0.1:8000 root@<HOST>
```
Re-print it any time with:
```bash
python deploy/demo_server.py tunnel
```

### 1d. Verify the model is reachable locally
```bash
curl http://127.0.0.1:8000/v1/models
```
Expected:
```json
{"object": "list", "data": [{"id": "harness", "object": "model"}]}
```

Now you are ready. Leave the box up and the tunnel open until the demo is done.

---

## 2. During the defense — the live scan

The scan needs a cases folder holding just the demo case, so it confirms in ~45s instead of
grinding through the whole benchmark. Build that folder once (the `repo/` is already checked out
under `benchmark/cases/`), then run the scan:

```bash
mkdir -p benchmark/demo-case && cp -r benchmark/cases/adb-driver_0.1.8 benchmark/demo-case/
```
```bash
python -m proofhound.evaluation.compare --models local-harness --cases benchmark/demo-case --out runs/demo --ground-truth-only
```

Run the `cp` line before the defense too — then the live step is a single command.

### What to narrate while it runs (~45–60s)
- The Analyzer found a **command-injection** candidate in `adb-driver` at `build/AdbDriver.js:26:25`.
- The **14B model** writes a JavaScript fuzzing harness that drives `execADBCommand(...)`.
- Jazzer.js fuzzes it **inside Docker**; the input reaches `child_process.exec` (the sink) and crashes.
- The crash is the **proof** — not a guess, an actual reproduction.

### Expected output (success)
```
[adb-driver_0.1.8] 1 finding(s) (ground_truth only)
Call chain:
  1. execADBCommand(command: string, option: unknown)
  2. exec(cmd: string, cb: function)  -> sink
  [local-harness] confirmed in 1 attempt(s) | ~1,135 tokens | ~44.0s
...
model          findings  errors  syntax_ok  loaded   reached  confirmed
local-harness  1         0       1 (100%)   1        1        1 (100%)
```
The headline: **confirmed = 1**. The model proved a real command-injection.

### Optional — show the broader benchmark
If asked how it does across many CVEs, show the saved results instead of running live:
```bash
cat experiments/results/RESULTS_TABLE.md
```
(Local 14B v8 confirmed 63% of the 27 ground-truth CVEs — beating GPT-6 / Gemini / Kimi on the same set.)

---

## 3. After the defense — stop billing (do not skip)

```bash
python deploy/demo_server.py down
```
It destroys the box and prints `verifying none left: []`. Double-check nothing is left:
```bash
python deploy/demo_server.py status
```

---

## 4. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `curl` to `:8000` hangs / refused | The tunnel dropped. Re-run the `ssh ... -L 8000:...` command (get it from `demo_server.py tunnel`). |
| SSH "timed out during banner exchange" | The box is busy downloading. Wait 30s and retry; vast.ai SSH is flaky under load. |
| Model not ready yet | SSH in and read the log: `ssh -i ~/.ssh/vast_proofhound -p <PORT> root@<HOST> "cat /root/serve.log"`. Look for `model ready`. |
| Docker not running / fuzzing errors | Start Docker Desktop; if it crashes, run the stale-socket fix in step 1a. |
| Scan says `skipped` / `not confirmed` | Use the prepared `benchmark/demo-case` (adb-driver), which is verified to confirm. Avoid live-running random cases. |
| Box rented but no model | Don't run `up` again (double-billing). `status` to get the box, SSH in, check `tmux ls` and `/root/serve.log`. |

## 5. Fallback (if the network fails live)

Before the defense, run step 2 once and **screen-record it** (or screenshot the `confirmed = 1`
summary). If the live network dies, show the recording — the result is identical.
