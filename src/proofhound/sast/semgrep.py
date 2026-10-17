"""Runs Semgrep and converts its JSON output into Findings.

Preferred: Docker image (keeps the host environment clean and pinned).
Fallback: native `semgrep` on PATH or in the active venv when Docker is unavailable.
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from proofhound.models import Finding, Severity
from proofhound.sast.base import SastEngine

IMAGE = "semgrep/semgrep:latest"
_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
# Our rules start their message with "[source: $P] [sink: $SINK]".
_SOURCE_SINK = re.compile(r"^\[source: (.*?)\] \[sink: (.*?)\]\s*", re.DOTALL)


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _semgrep_binary() -> str | None:
    """Return the path to a native semgrep binary, or None if not found."""
    # Prefer the one in the same venv as this interpreter.
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    venv_bin_exe = venv_bin.with_suffix(".exe")
    if venv_bin_exe.exists():
        return str(venv_bin_exe)
    return shutil.which("semgrep")


class SemgrepEngine(SastEngine):
    def __init__(self, image: str = IMAGE, timeout_s: int = 300):
        self.image = image
        self.timeout_s = timeout_s

    def scan(self, files: list[Path], rules_dir: Path, root: Path = Path(".")) -> list[Finding]:
        if not files:
            return []
        if _docker_available():
            return self._scan_docker(files, rules_dir, root)
        native = _semgrep_binary()
        if native:
            return self._scan_native(native, files, rules_dir, root)
        raise RuntimeError(
            "Neither Docker nor a native `semgrep` binary is available. "
            "Start Docker Desktop or run `pip install semgrep`."
        )

    def _scan_docker(self, files: list[Path], rules_dir: Path, root: Path) -> list[Finding]:
        proc = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none", "-e", "HOME=/tmp",
                "-v", f"{root.resolve()}:/src:ro",
                "-v", f"{rules_dir.resolve()}:/rules:ro",
                "-w", "/src", self.image,
                "semgrep", "scan", "--config", "/rules", "--json", "--quiet",
                "--metrics=off", "--disable-version-check",
                *(f.as_posix() for f in files),
            ],
            capture_output=True, text=True, encoding="utf-8", timeout=self.timeout_s,
            check=False,
        )
        return self._parse(proc.stdout, proc.stderr)

    def _scan_native(
        self, binary: str, files: list[Path], rules_dir: Path, root: Path
    ) -> list[Finding]:
        # Run with the repo root as cwd so file paths in output match what Docker would produce.
        proc = subprocess.run(
            [
                binary, "scan", "--config", str(rules_dir.resolve()),
                "--json", "--quiet", "--metrics=off", "--disable-version-check",
                *(str(root.resolve() / f) for f in files),
            ],
            capture_output=True, text=True, encoding="utf-8", timeout=self.timeout_s,
            check=False, cwd=str(root.resolve()),
        )
        # Native semgrep emits absolute paths; normalise them back to repo-relative.
        findings = self._parse(proc.stdout, proc.stderr)
        root_resolved = root.resolve()
        return [
            f.model_copy(update={"file": f.file.relative_to(root_resolved)})
            if f.file.is_absolute() else f
            for f in findings
        ]

    def _parse(self, stdout: str, stderr: str) -> list[Finding]:
        if not stdout.strip():
            raise RuntimeError(f"semgrep produced no output:\n{stderr[-2000:]}")
        report = json.loads(stdout)
        if report.get("errors"):
            messages = "; ".join(e.get("message", "")[:200] for e in report["errors"])
            raise RuntimeError(f"semgrep errors: {messages}")
        return [to_finding(r) for r in report["results"]]


def to_finding(result: dict) -> Finding:
    extra = result["extra"]
    message = extra["message"]
    source = sink = None
    if m := _SOURCE_SINK.match(message):
        source, sink = m.group(1), " ".join(m.group(2).split())
        message = message[m.end():]
        if source.startswith("$"):  # request-data sources do not bind $P
            source = None
    rule_id = result["check_id"].removeprefix("rules.")
    line = result["start"]["line"]
    key = f"{rule_id}|{result['path']}|{line}|{result['start']['col']}"
    return Finding(
        id=hashlib.sha1(key.encode()).hexdigest()[:10],
        rule_id=rule_id,
        severity=_SEVERITY.get(extra["severity"], Severity.MEDIUM),
        message=" ".join(message.split()),
        file=Path(result["path"]),
        line=line,
        source=source,
        sink=sink,
        vuln_class=extra.get("metadata", {}).get("vuln_class"),
    )
