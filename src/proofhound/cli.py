"""Command-line entry point: `proofhound scan`."""

import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console

from proofhound import __version__
from proofhound.adapters import get_adapter
from proofhound.adapters.javascript import JavaScriptAdapter
from proofhound.agents.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.agents.fuzzer import FuzzerAgent
from proofhound.agents.harness import HarnessAgent
from proofhound.config import load_settings
from proofhound.datalog.logger import AttemptLogger
from proofhound.llm.client import build_client
from proofhound.models import FindingStatus, RunReport
from proofhound.orchestrator.pipeline import Pipeline
from proofhound.sandbox.docker_runner import DockerSandbox
from proofhound.sast.semgrep import SemgrepEngine

app = typer.Typer(help="ProofHound: prove vulnerabilities instead of guessing.")
console = Console()


@app.callback()
def _load_env() -> None:
    from dotenv import load_dotenv

    load_dotenv(override=True)  # API keys live in .env; it wins over stale OS variables


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
    language: str = typer.Option(
        None, help="javascript | python. Defaults to the config's language."
    ),
) -> None:
    """List SAST findings on the functions changed by a commit (no fuzzing)."""
    settings = load_settings(config)
    lang = language or settings.language
    adapter = get_adapter(lang)
    rules_dir = settings.sast.rules_dir if lang == "javascript" else Path(f"rules/semgrep/{lang}")
    analyzer = AnalyzerAgent(adapter, SemgrepEngine(), rules_dir)
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
        None,
        help="Use hand-written harnesses (<function>.js) instead of the LLM. "
        "No API key needed; used for testing and the demo fallback.",
    ),
) -> None:
    """Analyze a commit, generate harnesses, and confirm findings by fuzzing."""
    settings = load_settings(config)
    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    attempt_logger = AttemptLogger(Path("training/data/harness_attempts.jsonl"))
    if harness_dir is not None:
        from proofhound.orchestrator.manual_harness import ManualHarnessStep

        harness_agent = ManualHarnessStep(harness_dir)
    else:
        try:
            model_config = settings.models[settings.harness.model]
        except KeyError as e:
            raise typer.BadParameter(
                f"Harness model '{settings.harness.model}' is missing from the config models "
                "section."
            ) from e
        harness_agent = HarnessAgent(
            client=build_client(settings.harness.model, model_config),
            model=model_config.model or settings.harness.model,
            adapter=adapter,
            sandbox=sandbox,
            settings=settings.harness,
            logger=attempt_logger,
        )
    sha = _resolve(repo, commit)
    pipeline = Pipeline(
        settings,
        AnalyzerAgent(adapter, SemgrepEngine(), settings.sast.rules_dir),
        harness_agent,
        FuzzerAgent(sandbox, adapter, attempt_logger=attempt_logger),
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
        conf = f"  confidence={r.confidence:.2f}" if r.confidence is not None else ""
        console.print(f"\n[{r.status.value.upper()}] {f.rule_id}  {where}  {fn}(){conf}")
        for c in r.crashes:
            console.print(f"  {c.kind} at {c.sink_location}  reproduced {c.reproduced}x")
            console.print(f"  input: {c.input_path}")
        if r.detail:
            console.print(f"  {r.detail}")


@app.command("benchmark-sast")
def benchmark_sast(
    cases: Path = typer.Option(Path("benchmark/cases"), help="Directory of built cases."),
    out: Path = typer.Option(Path("experiments/results/sast.json"), help="Output file."),
    config: Path = typer.Option(Path("configs/default.yaml"), help="Config file."),
) -> None:
    """Score the Analyzer (SAST only) against each case's ground-truth sink."""
    from proofhound.benchmark.runner import run_sast_benchmark

    settings = load_settings(config)
    analyzer = AnalyzerAgent(JavaScriptAdapter(), SemgrepEngine(), settings.sast.rules_dir)
    results = run_sast_benchmark(analyzer, cases, out)
    for r in results:
        mark = "ERROR" if r.error else ("hit " if r.detected else "miss")
        console.print(
            f"{mark}  {r.case:<34} {r.vuln_class:<18} findings={r.findings:<3} "
            f"fp={r.false_positives:<3} {r.error}"
        )
    scored = [r for r in results if not r.error]
    detected = sum(r.detected for r in scored)
    fps = sum(r.false_positives for r in scored)
    console.print(f"\nDetected {detected}/{len(scored)}   SAST false positives: {fps}   -> {out}")


@app.command("compare-models")
def compare_models(
    cases: Path = typer.Option(Path("benchmark/cases"), help="Directory of pre-built benchmark cases."),
    config: Path = typer.Option(Path("configs/default.yaml"), help="Config file."),
    models: list[str] = typer.Option(..., "--model", help="Model key from config (repeat for each model to compare)."),
    out: Path = typer.Option(Path("runs/compare"), help="Output directory for logs and summary."),
    max_cases: int = typer.Option(None, help="Stop after this many cases (smoke test)."),
) -> None:
    """Compare harness models end to end (Docker). Runs training/compare_models.py.

    Example: proofhound compare-models --model local-harness --model codecraft-claude
    """
    cmd = [
        sys.executable, "training/compare_models.py", "--cases", str(cases),
        "--config", str(config), "--out", str(out), "--models", *models,
    ]
    if max_cases is not None:
        cmd += ["--max-cases", str(max_cases)]
    raise SystemExit(subprocess.run(cmd, check=False).returncode)


@app.command()
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
