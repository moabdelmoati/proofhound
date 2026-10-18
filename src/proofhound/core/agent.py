"""Common shape for every agent: a fixed role, a prompt, and a tool set."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

In = TypeVar("In")
Out = TypeVar("Out")


class Agent(ABC, Generic[In, Out]):
    name: str = "agent"

    @abstractmethod
    def run(self, data: In) -> Out: ...
