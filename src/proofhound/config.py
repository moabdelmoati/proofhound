"""Loads configs/*.yaml into typed settings."""

from pathlib import Path

import yaml
from pydantic import BaseModel


class Budgets(BaseModel):
    run_timeout_s: int = 900
    fuzz_time_per_target_s: int = 30
    max_tokens_per_run: int = 200_000


class HarnessSettings(BaseModel):
    small_model_repair_attempts: int = 2
    large_model_repair_attempts: int = 2
    use_sast_hints: bool = True


class SandboxSettings(BaseModel):
    image: str = "proofhound/jazzerjs:latest"
    network: str = "none"
    memory: str = "2g"
    cpus: float = 2


class SastSettings(BaseModel):
    engine: str = "semgrep"
    rules_dir: Path = Path("rules/semgrep/javascript")


class CascadeSettings(BaseModel):
    enabled: bool = False
    triage_escalation_confidence: float = 0.6


class OutputSettings(BaseModel):
    dir: Path = Path("runs")
    formats: list[str] = ["json", "sarif"]


class Settings(BaseModel):
    language: str = "javascript"
    budgets: Budgets = Budgets()
    harness: HarnessSettings = HarnessSettings()
    sandbox: SandboxSettings = SandboxSettings()
    sast: SastSettings = SastSettings()
    cascade: CascadeSettings = CascadeSettings()
    output: OutputSettings = OutputSettings()


def load_settings(path: Path) -> Settings:
    with path.open(encoding="utf-8") as f:
        return Settings.model_validate(yaml.safe_load(f) or {})
