"""
ProofHound — Evaluate Prompt v4 on all benchmark cases.
Executes the exact logic from training/evaluate/eval_v4_full.ipynb.
"""
import subprocess, sys, time, os, json, textwrap
from pathlib import Path
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT    = Path(".").resolve()
PY      = ROOT / ".venv/Scripts/python.exe"
ADAPTER = ROOT / "models/harness-adapter-7b-v3-2048"
BASE    = "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit"
PORT    = 8000
OUT     = ROOT / "runs/compare-v4-full"

assert PY.exists(),      f"venv not found at {PY}"
assert ADAPTER.exists(), f"adapter not found at {ADAPTER}"

print(f"[*] Root: {ROOT}")
print(f"[*] Adapter: {ADAPTER.name}")
print(f"[*] Output dir: {OUT}", flush=True)

def _port_pid(port):
    try:
        r = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True
        )
        for line in r.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                return int(line.strip().split()[-1])
    except Exception:
        pass
    return None

def stop_server():
    pid = _port_pid(PORT)
    if pid:
        print(f"[*] Killing existing server on port {PORT} (PID {pid})...", flush=True)
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True)
        for _ in range(30):
            time.sleep(1)
            if not _port_pid(PORT):
                break
        print("[*] Server stopped.", flush=True)
    else:
        print(f"[*] No server running on port {PORT}.", flush=True)

# Step 1: Ensure any old server is stopped
stop_server()

srv = None
try:
    # Step 2: Start 7B inference server
    serve_log = OUT.parent / "serve-v4-full.log"
    OUT.parent.mkdir(parents=True, exist_ok=True)

    env = {**os.environ, "HF_HUB_OFFLINE": "1", "PYTHONUTF8": "1"}
    print(f"[*] Starting inference server on port {PORT} (log: {serve_log})...", flush=True)
    srv = subprocess.Popen(
        [str(PY), "training/serve/serve_local.py",
         "--adapter", str(ADAPTER),
         "--base",    BASE,
         "--device",  "cuda",
         "--load-4bit",
         "--port",    str(PORT)],
        cwd=str(ROOT), env=env,
        stdout=open(serve_log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )

    print(f"[*] Server PID {srv.pid} — waiting for it to be ready (up to 5 min)...", flush=True)
    ready = False
    for i in range(100):
        time.sleep(3)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/v1/models", timeout=2) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            if i % 10 == 9:
                print(f"    still loading ({(i+1)*3}s)...", flush=True)

    if not ready:
        print(f"[!] Server did not start — check {serve_log}", flush=True)
        if srv:
            srv.kill()
        raise RuntimeError("Server startup failed")

    print(f"[OK] Server ready after {(i+1)*3}s!", flush=True)

    # Step 3: Run evaluation compare
    compare_log = ROOT / "runs" / "compare-v4-full.log"
    print(f"[*] Starting evaluation on benchmark cases (progress every 5 cases)...", flush=True)
    print(f"[*] Log: {compare_log}", flush=True)

    proc = subprocess.Popen(
        [str(PY), "-m", "proofhound.evaluation.compare",
         "--models",         "local-harness",
         "--out",            str(OUT),
         "--progress-every", "5"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONUTF8": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    with open(compare_log, "w", encoding="utf-8") as log_f:
        for line in proc.stdout:
            print(line, end="", flush=True)
            log_f.write(line)

    proc.wait()
    print(f"\n[OK] Compare process finished with code {proc.returncode}", flush=True)

finally:
    # Step 4: Always clean up server
    print("[*] Cleaning up: stopping inference server...", flush=True)
    stop_server()

# Step 5: Display results
summary = OUT / "summary.json"
if not summary.exists():
    print(f"[!] summary.json not found at {summary} — run did not complete", flush=True)
else:
    data = json.loads(summary.read_text(encoding="utf-8"))
    models = data.get("models", [])
    by_class = data.get("by_class", [])

    def pct_bar(label, n, total, width=30):
        pct = n / max(total, 1)
        filled = int(pct * width)
        bar = "#" * filled + "-" * (width - filled)
        return f"{label:<12} |{bar}| {n}/{total} ({100*pct:.0f}%)"

    for row in models:
        model = row["model"]
        n = row["findings"]
        print(f"\n{'='*55}")
        print(f"  {model}  —  {n} findings,  {row['errors']} errors")
        print(f"{'='*55}")
        for stage in ("syntax_ok", "loaded", "reached", "confirmed"):
            val = row[stage]
            count = int(val.split()[0]) if isinstance(val, str) else val
            print(pct_bar(stage, count, n))
        print(f"  avg {row['avg_tokens']:,} tokens / {row['avg_seconds']}s per finding")

    print("\n── by vuln class ──")
    for row in by_class:
        n = row["findings"]
        reached_val = row["reached"]
        reached_n = int(reached_val.split()[0]) if isinstance(reached_val, str) else reached_val
        confirmed_val = row["confirmed"]
        confirmed_n = int(confirmed_val.split()[0]) if isinstance(confirmed_val, str) else confirmed_val
        print(f"  {row['vuln_class']:<25} reached {reached_n}/{n}  confirmed {confirmed_n}/{n}")

    STAGES = ("syntax_ok", "loaded", "reached", "confirmed")
    per = data.get("per_finding", [])
    if per:
        print(f"\n{'case':<35} {'class':<22} {'best stage'}")
        print("-" * 75)
        for r in per:
            best = next((s for s in reversed(STAGES) if r.get(s)), "failed")
            print(f"{r['case']:<35} {r['vuln_class']:<22} {best}")
