"""Thin interface over the large model (API) and our small model (local endpoint + LoRA adapter)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Completion:
    text: str
    tokens_used: int


class LLMClient(ABC):
    @abstractmethod
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> Completion: ...
