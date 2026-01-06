from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from static.models import Finding
    from static.secrets import SecretDetectionEngine


class WorkflowRule(ABC):
    platforms: set[str] = {"github"}

    @abstractmethod
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        raise NotImplementedError
