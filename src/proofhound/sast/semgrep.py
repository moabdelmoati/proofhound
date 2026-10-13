"""Runs Semgrep (in Docker) and converts its JSON output into Findings."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

from proofhound.models import Finding, Severity
from proofhound.sast.base import SastEngine

IMAGE = "semgrep/semgrep:latest"
_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
# Our rules start their message with "[source: $P] [sink: $SINK]".
_SOURCE_SINK = re.compile(r"^\[source: (.*?)\] \[sink: (.*?)\]\s*", re.DOTALL)


class SemgrepEngine(SastEngine):
    def __init__(self, image: str = IMAGE, timeout_s: int = 300):
        self.image = image
        self.timeout_s = timeout_s

    def scan(self, files: list[Path], rules_dir: Path, root: Path = Path(".")) -> list[Finding]:
        if not files:
            return []
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
        )
        if not proc.stdout.strip():
            raise RuntimeError(f"semgrep produced no output:\n{proc.stderr[-2000:]}")
        report = json.loads(proc.stdout)
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
