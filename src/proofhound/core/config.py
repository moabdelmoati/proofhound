"""Loads configs/*.yaml into typed settings."""

from pathlib import Path

import yaml
from pydantic import BaseModel

from proofhound.core.llm.client import ModelConfig


class Budgets(BaseModel):
    run_timeout_s: int = 900
    fuzz_time_per_target_s: int = 30
    max_tokens_per_run: int = 200_000


class HarnessSettings(BaseModel):
    model: str = "claude"  # key in `models`
    probe_time_s: int = 5  # short fuzz run used to check coverage growth
    small_model_repair_attempts: int = 2
    large_model_repair_attempts: int = 2
    use_sast_hints: bool = True
    class_seeds: bool = True
    rejection_sampling: bool = False
    call_chain_v2: bool = True


class SingleAgentSettings(BaseModel):
    model: str = "codecraft-claude"  # key in `models`
    max_steps: int = 30  # model calls per run; the run budget also applies


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
    formats: list[str] = ["json"]


class Settings(BaseModel):
    language: str = "javascript"
    budgets: Budgets = Budgets()
    harness: HarnessSettings = HarnessSettings()
    single_agent: SingleAgentSettings = SingleAgentSettings()
    sandbox: SandboxSettings = SandboxSettings()
    sast: SastSettings = SastSettings()
    cascade: CascadeSettings = CascadeSettings()
    output: OutputSettings = OutputSettings()
    models: dict[str, ModelConfig] = {}


def load_settings(path: Path) -> Settings:
    import os

    with path.open(encoding="utf-8") as f:
        settings = Settings.model_validate(yaml.safe_load(f) or {})
    # CI / remote serving: point the local-harness model at a served endpoint without editing the
    # config. MODEL_ENDPOINT is the OpenAI-compatible base URL (e.g. an SSH-tunnelled GPU box or an
    # HF Inference Endpoint). See deploy/README.md.
    endpoint = os.environ.get("MODEL_ENDPOINT")
    if endpoint and "local-harness" in settings.models:
        settings.models["local-harness"].base_url = endpoint
    return settings
