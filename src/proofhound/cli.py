"""Command-line entry point: `proofhound scan` (single or multi agent), analysis and evaluation."""

import subprocess
from pathlib import Path

import typer
from rich.console import Console

from proofhound import __version__
from proofhound.core.adapters import get_adapter
from proofhound.core.adapters.javascript import JavaScriptAdapter
from proofhound.core.analysis.analyzer import AnalyzeJob, AnalyzerAgent
from proofhound.core.analysis.semgrep import SemgrepEngine
from proofhound.core.config import Settings, load_settings
from proofhound.core.datalog.logger import AttemptLogger
from proofhound.core.fuzzing.fuzzer import FuzzerAgent
from proofhound.core.fuzzing.sandbox import DockerSandbox
from proofhound.core.harness.agent import HarnessAgent
from proofhound.core.llm.client import ModelConfig, build_client
from proofhound.core.models import FindingStatus, RunReport
from proofhound.multi_agent.pipeline import Pipeline

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
    agent: str = typer.Option(
        "single", help="single: one LLM drives every tool (Term 1). "
        "multi: the specialized-agent pipeline (Term 2).",
    ),
    model: str = typer.Option(
        None, help="Model key from the config. Defaults to single_agent.model or harness.model.",
    ),
    harness_dir: Path = typer.Option(
        None,
        help="--agent multi only: use hand-written harnesses (<function>.js) instead of the LLM. "
        "No API key needed; used for testing and the demo fallback.",
    ),
) -> None:
    """Analyze a commit, write harnesses, and prove findings by fuzzing."""
    if agent not in {"single", "multi"}:
        raise typer.BadParameter("--agent must be 'single' or 'multi'")
    if harness_dir is not None and agent != "multi":
        raise typer.BadParameter("--harness-dir only applies to --agent multi")
    settings = load_settings(config)
    sha = _resolve(repo, commit)
    if agent == "single":
        _scan_single(settings, repo, sha, model)
    else:
        _scan_multi(settings, repo, sha, model, harness_dir)


def _model_config(settings: Settings, key: str) -> ModelConfig:
    try:
        return settings.models[key]
    except KeyError as e:
        raise typer.BadParameter(
            f"Model '{key}' is missing from the config's models section."
        ) from e


def _scan_single(settings: Settings, repo: Path, sha: str, model: str | None) -> None:
    from proofhound.single_agent.runner import scan_commit

    key = model or settings.single_agent.model
    _model_config(settings, key)
    run_dir = settings.output.dir / f"{sha[:12]}-single"
    report, result = scan_commit(settings, repo, sha, run_dir, model_key=key)
    _print_summary(report)
    console.print(
        f"\nSingle agent ({key}): {len(result.steps)} steps, stopped: {result.stop_reason}, "
        f"protocol errors: {result.protocol_errors}, tokens: {result.tokens_used:,}"
    )
    console.print(f"Report: {run_dir / 'report.json'}   Transcript: {run_dir / 'transcript.jsonl'}")


def _scan_multi(
    settings: Settings, repo: Path, sha: str, model: str | None, harness_dir: Path | None,
) -> None:
    adapter = JavaScriptAdapter()
    sandbox = DockerSandbox(settings.sandbox)
    attempt_logger = AttemptLogger(Path("training/data/harness_attempts.jsonl"))
    if harness_dir is not None:
        from proofhound.multi_agent.manual_harness import ManualHarnessStep

        harness_agent = ManualHarnessStep(harness_dir)
    else:
        key = model or settings.harness.model
        model_config = _model_config(settings, key)
        harness_agent = HarnessAgent(
            client=build_client(key, model_config),
            model=model_config.model or key,
            adapter=adapter,
            sandbox=sandbox,
            settings=settings.harness,
            logger=attempt_logger,
        )
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
    from proofhound.evaluation.sast_benchmark import run_sast_benchmark

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
    """Compare harness models end to end (Docker).

    Example: proofhound compare-models --model local-harness --model codecraft-claude
    """
    from proofhound.evaluation.compare import main as compare_main

    argv = ["--cases", str(cases), "--config", str(config), "--out", str(out), "--models", *models]
    if max_cases is not None:
        argv += ["--max-cases", str(max_cases)]
    compare_main(argv)


@app.command()
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
