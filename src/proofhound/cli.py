"""Command-line entry point: `proofhound scan`."""

import subprocess
from pathlib import Path

import typer
from rich.console import Console

from proofhound import __version__
from proofhound.adapters.javascript import JavaScriptAdapter
from proofhound.agents.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.agents.fuzzer import FuzzerAgent
from proofhound.config import load_settings
from proofhound.models import FindingStatus, RunReport
from proofhound.orchestrator.manual_harness import ManualHarnessStep
from proofhound.orchestrator.pipeline import Pipeline
from proofhound.sandbox.docker_runner import DockerSandbox
from proofhound.sast.semgrep import SemgrepEngine

app = typer.Typer(help="ProofHound: prove vulnerabilities instead of guessing.")
console = Console()


def _resolve(repo: Path, commit: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", commit],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


@app.command()
def analyze(
    repo: Path = typer.Option(Path("."), help="Path to the git repository."),
    commit: str = typer.Option("HEAD", help="Commit to analyze against its parent."),
    config: Path = typer.Option(Path("configs/default.yaml"), help="Config file."),
) -> None:
    """List SAST findings on the functions changed by a commit (no fuzzing)."""
    settings = load_settings(config)
    analyzer = AnalyzerAgent(JavaScriptAdapter(), SemgrepEngine(), settings.sast.rules_dir)
    analysis = analyzer.run(AnalyzeJob(repo, _resolve(repo, commit)))
    console.print(
        f"Changed functions: {len(analysis.changed_functions)}   "
        f"SAST findings: {analysis.all_sast_findings}   "
        f"In changed functions: {len(analysis.findings)}"
    )
    for f in analysis.findings:
        fn = f.function.name if f.function else "?"
        console.print(f"  [{f.severity.value}] {f.rule_id}  {f.file.as_posix()}:{f.line}  {fn}")


@app.command()
def scan(
    repo: Path = typer.Option(Path("."), help="Path to the git repository."),
    commit: str = typer.Option("HEAD", help="Commit to analyze against its parent."),
    config: Path = typer.Option(Path("configs/default.yaml"), help="Config file."),
    harness_dir: Path = typer.Option(
        ..., help="Directory of hand-written harnesses named <function>.js."
    ),
) -> None:
    """Analyze a commit's changed functions and confirm findings by fuzzing."""
    settings = load_settings(config)
    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    sha = _resolve(repo, commit)
    pipeline = Pipeline(
        settings,
        AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir),
        ManualHarnessStep(harness_dir),
        FuzzerAgent(sandbox, adapter),
        adapter,
    )
    run_dir = settings.output.dir / sha[:12]
    report = pipeline.run(repo, sha, run_dir)
    _print_summary(report)
    console.print(f"\nReport: {run_dir / 'report.json'}")


def _print_summary(report: RunReport) -> None:
    console.print(
        f"Changed functions: {report.changed_functions}   "
        f"SAST findings: {report.sast_findings_total}   "
        f"Confirmed: {report.count(FindingStatus.CONFIRMED)}   "
        f"({report.duration_s:.0f}s)"
    )
    for r in report.results:
        f = r.finding
        where = f"{f.file.as_posix()}:{f.line}"
        fn = f.function.name if f.function else "?"
        console.print(f"\n[{r.status.value.upper()}] {f.rule_id}  {where}  {fn}()")
        for c in r.crashes:
            console.print(f"  {c.kind} at {c.sink_location}  reproduced {c.reproduced}x")
            console.print(f"  input: {c.input_path}")
        if r.detail:
            console.print(f"  {r.detail}")


@app.command()
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
