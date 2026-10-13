"""Command-line entry point: `proofhound scan`."""

from pathlib import Path

import typer

from proofhound import __version__

app = typer.Typer(help="ProofHound: prove vulnerabilities instead of guessing.")


@app.command()
def scan(
    repo: Path = typer.Option(Path("."), help="Path to the git repository."),
    commit: str = typer.Option("HEAD", help="Commit to analyze against its parent."),
    config: Path = typer.Option(Path("configs/default.yaml"), help="Config file."),
) -> None:
    """Analyze the changed functions of a commit and confirm findings by fuzzing."""
    raise NotImplementedError("Pipeline is implemented in phase T1-D.")


@app.command()
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
