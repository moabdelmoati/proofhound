"""Publish the v8 LoRA adapter to a public HuggingFace repo so a serving box can pull it keyless.

    set HF_TOKEN=...            # a write token from huggingface.co/settings/tokens
    python deploy/upload_adapter_hf.py

Prints the repo id. Point the serving box / CI at it (no credentials needed to download a public
repo). Run this yourself — it publishes a model publicly, which is your call, not the assistant's.
"""
import os
import sys
from pathlib import Path

from huggingface_hub import HfApi

ADAPTER = Path(__file__).resolve().parent.parent / "models" / "harness-adapter-14b-v8"


def main() -> None:
    token = os.environ.get("HF_TOKEN")
    if not token:
        sys.exit("set HF_TOKEN first (a write token from huggingface.co/settings/tokens)")
    if not ADAPTER.exists():
        sys.exit(f"adapter not found at {ADAPTER}")
    api = HfApi(token=token)
    user = api.whoami()["name"]
    repo = f"{user}/proofhound-harness-14b-v8"
    print(f"[*] creating public repo {repo} ...")
    api.create_repo(repo_id=repo, repo_type="model", private=False, exist_ok=True)
    print(f"[*] uploading {ADAPTER} ...")
    api.upload_folder(repo_id=repo, folder_path=str(ADAPTER), repo_type="model")
    print(f"\n[OK] published: https://huggingface.co/{repo}")
    print("Point the box / CI at it, e.g. in serve_box_setup.sh:")
    print(f'  huggingface-cli download {repo} --local-dir /root/adapter')


if __name__ == "__main__":
    main()
