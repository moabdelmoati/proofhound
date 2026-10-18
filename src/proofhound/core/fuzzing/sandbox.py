"""Runs generated code in Docker: no network, CPU/memory limits, read-only root, hard timeout.

Mounts:
  /work/target  the code under test (read-only)
  /work/out     harness, corpus, crash files, coverage (writable)
The working directory is a tmpfs, so files created by injected commands never reach the host.
"""

import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from proofhound.core.config import SandboxSettings

TARGET = "/work/target"
OUT = "/work/out"


@dataclass
class SandboxResult:
    exit_code: int
    output: str
    timed_out: bool
    duration_s: float


class DockerSandbox:
    def __init__(self, settings: SandboxSettings):
        self.settings = settings

    def run(
        self,
        command: list[str],
        target: Path,
        out: Path,
        timeout_s: float,
        image: str | None = None,
        network: bool = False,
    ) -> SandboxResult:
        """Run `command` in a fresh container. `network=True` is only for installing dependencies."""
        out.mkdir(parents=True, exist_ok=True)
        name = f"proofhound-{uuid.uuid4().hex[:12]}"
        args = [
            "docker", "run", "--rm", "--name", name,
            "--network", "bridge" if network else self.settings.network,
            "--memory", self.settings.memory,
            "--cpus", str(self.settings.cpus),
            "--pids-limit", "256",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:exec,size=256m",
            "-w", "/tmp",
            "-v", f"{target.resolve()}:{TARGET}:{'rw' if network else 'ro'}",
            "-v", f"{out.resolve()}:{OUT}",
            image or self.settings.image,
            *command,
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                check=False,
                timeout=timeout_s,
            )
            return SandboxResult(
                proc.returncode, proc.stdout + proc.stderr, False, time.monotonic() - start
            )
        except subprocess.TimeoutExpired as e:
            subprocess.run(["docker", "kill", name], capture_output=True, check=False)
            output = _as_text(e.stdout) + _as_text(e.stderr)
            return SandboxResult(-1, output, True, time.monotonic() - start)


def _as_text(stream: bytes | str | None) -> str:
    # TimeoutExpired carries bytes even when the process was started with text=True.
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return stream or ""
