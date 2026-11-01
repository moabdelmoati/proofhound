"""vast.ai control for the ProofHound cloud eval. One stable entry point so a single
permission rule (Bash(python -I scripts/vast_ctl.py:*)) can cover rent/manage/destroy.

Reads VAST_API_KEY from .env. Subcommands:

    python -I scripts/vast_ctl.py offers              # cheapest viable non-China 24GB offers
    python -I scripts/vast_ctl.py rent <offer_id>     # attach ssh key + create instance
    python -I scripts/vast_ctl.py show [<id>]         # list instances / one instance detail
    python -I scripts/vast_ctl.py ssh <id>            # print ssh host/port + ready-to-run cmd
    python -I scripts/vast_ctl.py destroy <id>        # destroy an instance (stops billing)
"""
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from vastai import VastAI

load_dotenv(r"C:\dev\proofhound\.env", override=True)
V = VastAI(api_key=os.environ["VAST_API_KEY"])
PUB = Path(os.path.expanduser("~/.ssh/vast_proofhound.pub"))

IMAGE = "pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime"
OFFER_QUERY = ("verified=true rentable=true num_gpus=1 gpu_ram>=22 disk_space>=60 "
               "reliability>=0.98 inet_down>=200 dph<=0.30 cuda_vers>=12.0")
BLOCK_GEO = ("CN", "China", "Russia", "RU")


def _rows(res):
    if isinstance(res, list):
        return res
    if isinstance(res, dict):
        return res.get("offers") or res.get("instances") or res.get("instance") or res
    return res


def offers():
    res = V.search_offers(query=OFFER_QUERY, order="dph_total", limit=50)
    rows = _rows(res)
    if isinstance(rows, str):
        print(rows[:2000]); return
    out = []
    for o in rows:
        geo = o.get("geolocation") or ""
        if any(c in geo for c in BLOCK_GEO):
            continue
        out.append({"id": o.get("id"), "gpu": o.get("gpu_name"),
                    "dph": round(o.get("dph_total", 0), 4), "disk": round(o.get("disk_space", 0)),
                    "down": round(o.get("inet_down", 0)), "reliab": round(o.get("reliability", 0), 3),
                    "geo": geo})
    out.sort(key=lambda r: r["dph"])
    print(json.dumps(out[:12], indent=2))


def rent(offer_id):
    pub = PUB.read_text().strip()
    try:
        V.create_ssh_key(ssh_key=pub)
    except Exception as e:
        print("ssh-key note:", type(e).__name__, str(e)[:160])
    r = V.create_instance(id=int(offer_id), image=IMAGE, disk=60, ssh=True, direct=True,
                          label="proofhound-eval")
    print(json.dumps(r, indent=2, default=str)[:1500])


def show(instance_id=None):
    if instance_id:
        print(json.dumps(_rows(V.show_instance(id=int(instance_id))), indent=2, default=str)[:2500])
    else:
        rows = _rows(V.show_instances())
        if isinstance(rows, str):
            print(rows[:2000]); return
        brief = [{"id": i.get("id"), "status": i.get("actual_status"),
                  "gpu": i.get("gpu_name"), "dph": i.get("dph_total"),
                  "ssh_host": i.get("ssh_host"), "ssh_port": i.get("ssh_port"),
                  "ip": i.get("public_ipaddr")} for i in (rows or [])]
        print(json.dumps(brief, indent=2, default=str))


def ssh(instance_id):
    i = _rows(V.show_instance(id=int(instance_id)))
    if isinstance(i, list) and i:
        i = i[0]
    host, port = i.get("ssh_host"), i.get("ssh_port")
    status = i.get("actual_status")
    print(json.dumps({"status": status, "ssh_host": host, "ssh_port": port,
                      "cmd": f'ssh -i ~/.ssh/vast_proofhound -p {port} root@{host}' if host else None},
                     indent=2, default=str))


def destroy(instance_id):
    print(json.dumps(V.destroy_instance(id=int(instance_id)), indent=2, default=str))


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd, rest = sys.argv[1], sys.argv[2:]
    {"offers": offers, "rent": rent, "show": show, "ssh": ssh, "destroy": destroy}[cmd](*rest)


if __name__ == "__main__":
    main()
