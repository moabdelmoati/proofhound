"""Per-run time and token budgets. Agents call `charge` and stop when `exhausted`."""

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    timeout_s: int
    max_tokens: int
    tokens_used: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def charge(self, tokens: int) -> None:
        self.tokens_used += tokens

    @property
    def exhausted(self) -> bool:
        elapsed = time.monotonic() - self.started_at
        return elapsed >= self.timeout_s or self.tokens_used >= self.max_tokens
