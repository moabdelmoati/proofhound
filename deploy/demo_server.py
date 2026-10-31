"""One-command demo server for ProofHound: rent a vast.ai GPU, serve the v8 model, tear it down.

    python deploy/demo_server.py up      # rent cheapest box, upload adapter, start serving
    python deploy/demo_server.py tunnel  # print the SSH tunnel command (serve -> localhost:8000)
    python deploy/demo_server.py down     # destroy the box (stops billing)
    python deploy/demo_server.py status   # show the current box

State (the instance id) is kept in deploy/.demo_instance so `down` knows what to destroy.
Needs: VAST_API_KEY in .env, the ssh key ~/.ssh/vast_proofhound, and the v8 adapter at
models/harness-adapter-14b-v8/. `up` prints the tunnel command when the model is ready.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = Path(__file__).resolve().parent / ".demo_instance"
KEY = Path.home() / ".ssh" / "vast_proofhound"
ADAPTER = ROOT / "models" / "harness-adapter-14b-v8"
SETUP = Path(__file__).resolve().parent / "serve_box_setup.sh"
VCTL = [sys.executable, "-I", str(ROOT / "scripts" / "vast_ctl.py")]


def _vctl(*args) -> str:
    return subprocess.run(VCTL + list(args), capture_output=True, text=True, cwd=ROOT).stdout


def _ssh_info(instance_id: str):
    import os
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=True)
    from vastai import VastAI
    v = VastAI(api_key=os.environ["VAST_API_KEY"])
    d = v.show_instance(id=int(instance_id))
    if isinstance(d, dict):
        return d.get("ssh_host"), d.get("ssh_port"), d.get("actual_status")
    return None, None, None


def _ssh(host, port, cmd, timeout=120):
    return subprocess.run(
        ["ssh", "-i", str(KEY), "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ConnectTimeout=25", f"root@{host}", cmd],
        capture_output=True, text=True, timeout=timeout)


def up():
    if not ADAPTER.exists():
        sys.exit(f"adapter not found at {ADAPTER} — download it from Kaggle first")
    print("[*] searching for the cheapest viable GPU offer...")
    offers = json.loads(_vctl("offers") or "[]")
    if not offers:
        sys.exit("no offers found (check VAST_API_KEY / connectivity)")
    offer = offers[0]
    print(f"[*] renting offer {offer['id']} ({offer['gpu']}, ${offer['dph']}/hr, {offer['geo']})...")
    res = _vctl("rent", str(offer["id"]))
    print(res)
    try:
        inst = str(json.loads(res.strip().splitlines()[-1] if "{" in res else res)["new_contract"])
    except Exception:
        # res may have a note line before the json
        inst = str(json.loads(res[res.index("{"):])["new_contract"])
    STATE.write_text(inst)
    print(f"[*] instance {inst} — waiting for SSH (up to 5 min)...")
    host = port = None
    for _ in range(30):
        time.sleep(10)
        host, port, st = _ssh_info(inst)
        if host and port and st == "running":
            break
    if not host:
        sys.exit(f"instance {inst} did not come up; run `down` to clean it up")
    print(f"[*] box up at {host}:{port}. Uploading adapter + setup...")
    subprocess.run(["ssh", "-i", str(KEY), "-p", str(port), "-o", "StrictHostKeyChecking=accept-new",
                    f"root@{host}", "mkdir -p /root/adapter"], check=True)
    subprocess.run(["scp", "-i", str(KEY), "-P", str(port), "-o", "StrictHostKeyChecking=accept-new",
                    str(SETUP), f"root@{host}:/root/serve_box_setup.sh"], check=True)
    for f in ADAPTER.iterdir():
        if f.is_file():
            subprocess.run(["scp", "-i", str(KEY), "-P", str(port), str(f),
                            f"root@{host}:/root/adapter/"], check=True)
    print("[*] running box setup (installs deps, starts serving)...")
    _ssh(host, port, "bash /root/serve_box_setup.sh", timeout=600)
    print("[*] waiting for the model to be ready (base model downloads ~10GB)...")
    for _ in range(40):
        time.sleep(15)
        r = _ssh(host, port, "tail -1 /root/serve.log 2>/dev/null; "
                             "curl -s -m 5 http://127.0.0.1:8000/v1/models 2>/dev/null")
        if "harness" in r.stdout:
            print("\n[OK] model ready!")
            tunnel()
            return
    print("[!] model not ready yet — check `tail -f /root/serve.log` on the box; "
          "once ready run `python deploy/demo_server.py tunnel`")


def tunnel():
    inst = STATE.read_text().strip() if STATE.exists() else None
    if not inst:
        sys.exit("no active instance (run `up` first)")
    host, port, _ = _ssh_info(inst)
    print("\nOpen the tunnel locally (keep this running), then compare.py hits 127.0.0.1:8000:\n")
    print(f'  ssh -i {KEY} -p {port} -N -L 8000:127.0.0.1:8000 root@{host}\n')
    print("Then run a scan, e.g.:")
    print("  python -m proofhound.evaluation.compare --models local-harness --cases benchmark/cases "
          "--out runs/demo --ground-truth-only --max-cases 1\n")


def status():
    inst = STATE.read_text().strip() if STATE.exists() else None
    if not inst:
        print("no active instance tracked.")
        return
    host, port, st = _ssh_info(inst)
    print(f"instance {inst}: status={st} ssh={host}:{port}")


def down():
    inst = STATE.read_text().strip() if STATE.exists() else None
    if not inst:
        print("no active instance tracked; listing all to be safe:")
        print(_vctl("show"))
        return
    print(f"[*] destroying instance {inst}...")
    print(_vctl("destroy", inst))
    STATE.unlink(missing_ok=True)
    print("[*] verifying none left:")
    print(_vctl("show"))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    {"up": up, "down": down, "tunnel": tunnel, "status": status}.get(cmd, status)()
