"""MCP server — exposes ProofHound as tools that Claude Code can call directly.

Usage (add to ~/.claude/settings.json or project .claude/settings.json):

  "mcpServers": {
    "proofhound": {
      "command": "python",
      "args": ["-m", "proofhound.mcp_server"],
      "env": {
        "MODEL_ENDPOINT": "http://your-gpu-box:8000/v1"   // optional; omit for SAST-only
      }
    }
  }

Or install the package first and use the entry point:
  "command": "proofhound-mcp"
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("proofhound")


def _run_cli(*args: str) -> tuple[int, str]:
    """Run the proofhound CLI in a subprocess; return (returncode, combined output)."""
    result = subprocess.run(
        [sys.executable, "-m", "proofhound.cli", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


@mcp.tool()
def analyze_commit(
    repo: str = ".",
    commit: str = "HEAD",
    config: str = "configs/default.yaml",
) -> str:
    """Run SAST-only analysis on the functions changed by a git commit.

    No GPU or Docker required — this is a fast first pass that surfaces
    candidate vulnerabilities before fuzzing.

    Args:
        repo:   Path to the git repository (default: current directory).
        commit: Git ref to analyze against its parent (default: HEAD).
        config: Path to a ProofHound config YAML (default: configs/default.yaml).

    Returns a plain-text summary of changed functions and SAST findings.
    """
    rc, out = _run_cli(
        "analyze",
        "--repo", repo,
        "--commit", commit,
        "--config", config,
    )
    if rc != 0:
        return f"ERROR (exit {rc}):\n{out}"
    return out


@mcp.tool()
def scan_commit(
    repo: str = ".",
    commit: str = "HEAD",
    config: str = "configs/default.yaml",
    agent: str = "multi",
    model: str | None = None,
) -> str:
    """Prove vulnerabilities in the functions changed by a git commit.

    Runs the full ProofHound pipeline: SAST → LLM harness generation → fuzzing.
    Requires Docker (for the Jazzer.js sandbox) and either MODEL_ENDPOINT set in
    the environment or an API key for a cloud model in the config.

    Args:
        repo:   Path to the git repository (default: current directory).
        commit: Git ref to analyze against its parent (default: HEAD).
        config: Path to a ProofHound config YAML (default: configs/default.yaml).
        agent:  'multi' (recommended) or 'single'.
        model:  Model key from the config; omit to use the config's default.

    Returns a JSON summary of confirmed/unconfirmed/reached findings.
    """
    extra: list[str] = []
    if model:
        extra += ["--model", model]

    rc, out = _run_cli(
        "scan",
        "--repo", repo,
        "--commit", commit,
        "--config", config,
        "--agent", agent,
        *extra,
    )
    if rc != 0:
        return f"ERROR (exit {rc}):\n{out}"

    # Try to parse the report.json that the pipeline writes to runs/<sha12>/
    sha_line = next((line for line in out.splitlines() if "Report:" in line), None)
    if sha_line:
        report_path = sha_line.split("Report:")[-1].split()[0].strip()
        try:
            report = json.loads(Path(report_path).read_text())
            return json.dumps(report, indent=2)
        except Exception:
            pass

    return out


@mcp.tool()
def list_benchmark_cases(
    cases_dir: str = "benchmark/cases",
) -> str:
    """List the available benchmark cases (CVE-backed JavaScript vulnerabilities).

    Useful for understanding what ProofHound can find and for running targeted
    evaluations with compare_models.

    Args:
        cases_dir: Path to the benchmark cases directory.

    Returns a newline-separated list of case names and their vulnerability class.
    """
    p = Path(cases_dir)
    if not p.exists():
        return f"Cases directory not found: {p.resolve()}"

    lines: list[str] = []
    for case_dir in sorted(p.iterdir()):
        if not case_dir.is_dir():
            continue
        meta_file = case_dir / "case.yaml"
        if not meta_file.exists():
            lines.append(case_dir.name)
            continue
        try:
            import yaml  # already a project dep
            meta = yaml.safe_load(meta_file.read_text())
            vuln = meta.get("vulnerability_class", "?")
            cve = meta.get("cve", "")
            lines.append(f"{case_dir.name:<40} {vuln:<20} {cve}")
        except Exception:
            lines.append(case_dir.name)

    if not lines:
        return f"No cases found in {p.resolve()}"
    header = f"{'Case':<40} {'Vuln class':<20} CVE\n" + "-" * 70
    return header + "\n" + "\n".join(lines)


@mcp.tool()
def proofhound_help() -> str:
    """Return a short guide to ProofHound's MCP tools and setup instructions."""
    return textwrap.dedent("""
        ProofHound MCP — prove vulnerabilities instead of guessing.

        Tools available:
          analyze_commit   SAST-only scan of a git commit's changed functions.
                           Fast, no GPU/Docker needed. Good first pass.

          scan_commit      Full pipeline: SAST → LLM harness → Jazzer.js fuzzing.
                           Needs Docker + MODEL_ENDPOINT (or a cloud model key).

          list_benchmark_cases  Show the CVE-backed JS benchmark cases.

        Quick start (from a JavaScript repo with ProofHound installed):
          1. Run analyze_commit to see what changed and what SAST flags.
          2. Run scan_commit on the same commit to confirm real exploitability.

        Configuration:
          Set MODEL_ENDPOINT in your environment (or in the mcpServers env block
          in settings.json) to point at an OpenAI-compatible GPU server running
          the ProofHound 14B adapter (see deploy/demo_server.py).

          Without MODEL_ENDPOINT you can still use cloud models — set
          ANTHROPIC_API_KEY or OPENAI_API_KEY and pick a model key from
          configs/default.yaml that maps to those providers.
    """).strip()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
