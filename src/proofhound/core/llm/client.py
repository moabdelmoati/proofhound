"""LLM clients behind one interface, so each agent can use a different model.

Providers:
  anthropic          Claude, via the Anthropic SDK
  openai             OpenAI models, via the OpenAI SDK
  openai_compatible  any OpenAI-compatible endpoint: Gemini's OpenAI endpoint, vLLM/Ollama
                     serving our fine-tuned small models
  fake               scripted replies, for tests

Every request is a single turn (system + one user prompt). Repair loops send the previous
attempt and its error in a fresh prompt instead of growing a conversation, which keeps the
agents provider-agnostic and every call independently logged.
"""

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from pydantic import BaseModel


class ModelConfig(BaseModel):
    provider: str  # anthropic | openai | openai_compatible | fake
    model: str = ""
    api_key_env: str | None = None
    # openai/openai_compatible: further key env vars, tried in order once a key runs out of quota
    fallback_key_envs: list[str] = []
    base_url: str | None = None
    effort: str | None = None  # anthropic: output_config.effort
    fallbacks: str | None = None  # anthropic: "default" enables server-side refusal fallback
    # Reasoning models spend hidden thinking tokens from this same budget before writing the answer.
    max_tokens: int = 16000
    temperature: float | None = None  # only sent to providers that accept it
    reasoning_effort: str | None = None  # openai/openai_compatible: low | medium | high


@dataclass
class Completion:
    text: str
    input_tokens: int
    output_tokens: int
    model: str
    stop_reason: str | None = None
    latency_s: float = 0.0
    reasoning_tokens: int = 0  # part of output_tokens; spent on hidden thinking, not the answer

    @property
    def tokens_used(self) -> int:
        return self.input_tokens + self.output_tokens


class LLMError(RuntimeError):
    pass


class LLMRefusal(LLMError):
    pass


class LLMClient(ABC):
    name: str

    @abstractmethod
    def complete(self, system: str, prompt: str) -> Completion: ...


class AnthropicClient(LLMClient):
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(self, name: str, cfg: ModelConfig):
        import anthropic

        self.name = name
        self.cfg = cfg
        key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        kwargs = {"base_url": cfg.base_url} if cfg.base_url else {}
        # Without an explicit key the SDK resolves ANTHROPIC_API_KEY / auth profiles itself.
        self.client = anthropic.Anthropic(api_key=key, **kwargs) if key else anthropic.Anthropic(**kwargs)

    def complete(self, system: str, prompt: str) -> Completion:
        kwargs: dict = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.cfg.effort:
            kwargs["output_config"] = {"effort": self.cfg.effort}
        start = time.monotonic()
        if self.cfg.fallbacks:
            response = self.client.beta.messages.create(
                **kwargs, betas=[self.FALLBACK_BETA], fallbacks=self.cfg.fallbacks
            )
        else:
            response = self.client.messages.create(**kwargs)
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            raise LLMRefusal(f"{self.name} refused: {getattr(details, 'category', None)}")
        text = "".join(b.text for b in response.content if b.type == "text")
        return Completion(
            text=text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=response.model,
            stop_reason=response.stop_reason,
            latency_s=time.monotonic() - start,
        )


_QUOTA_MARKERS = ("402", "429", "quota", "insufficient", "balance", "rate_limit")


def is_quota_error(error: Exception) -> bool:
    return any(m in str(error).lower() for m in _QUOTA_MARKERS)


class OpenAIClient(LLMClient):
    def __init__(self, name: str, cfg: ModelConfig):
        import openai

        self.name = name
        self.cfg = cfg
        self._openai = openai
        envs = [e for e in (cfg.api_key_env, *cfg.fallback_key_envs) if e]
        self._keys = [(e, os.environ[e]) for e in envs if os.environ.get(e)]
        self._key_index = 0
        self.client = self._connect()

    def _connect(self):
        if not self._keys:
            # Keyless means our local server: a slow laptop GPU, not a flaky network. A retry would
            # only queue the same generation again, so wait longer and never resend.
            return self._openai.OpenAI(
                api_key="not-needed", base_url=self.cfg.base_url, timeout=1800, max_retries=0,
            )
        return self._openai.OpenAI(api_key=self._keys[self._key_index][1], base_url=self.cfg.base_url)

    def _create(self, kwargs: dict):
        while True:
            try:
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:
                if not is_quota_error(e) or self._key_index + 1 >= len(self._keys):
                    raise
                old = self._keys[self._key_index][0]
                self._key_index += 1
                print(f"[{self.name}] {old} out of quota; switching to {self._keys[self._key_index][0]}")
                self.client = self._connect()

    def complete(self, system: str, prompt: str) -> Completion:
        kwargs: dict = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_completion_tokens": self.cfg.max_tokens,
        }
        if self.cfg.temperature is not None:
            kwargs["temperature"] = self.cfg.temperature
        if self.cfg.reasoning_effort:
            kwargs["reasoning_effort"] = self.cfg.reasoning_effort
        start = time.monotonic()
        response = self._create(kwargs)
        choice = response.choices[0]
        usage = response.usage
        details = getattr(usage, "completion_tokens_details", None)
        return Completion(
            text=choice.message.content or "",
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=response.model,
            stop_reason=choice.finish_reason,
            latency_s=time.monotonic() - start,
            reasoning_tokens=getattr(details, "reasoning_tokens", None) or 0,
        )


@dataclass
class FakeClient(LLMClient):
    """Returns scripted replies in order; records every prompt it was sent."""

    replies: list[str]
    name: str = "fake"
    prompts: list[str] = field(default_factory=list)

    def complete(self, system: str, prompt: str) -> Completion:
        self.prompts.append(prompt)
        if not self.replies:
            raise LLMError("FakeClient ran out of replies")
        text = self.replies.pop(0)
        return Completion(text, len(prompt) // 4, len(text) // 4, "fake", "end_turn")


def build_client(name: str, cfg: ModelConfig) -> LLMClient:
    if cfg.provider == "anthropic":
        return AnthropicClient(name, cfg)
    if cfg.provider in ("openai", "openai_compatible"):
        return OpenAIClient(name, cfg)
    if cfg.provider == "fake":
        return FakeClient(replies=[], name=name)
    raise ValueError(f"unknown LLM provider: {cfg.provider}")
