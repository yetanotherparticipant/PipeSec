from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from static.models import Finding


class NotificationChannel(ABC):
    @abstractmethod
    def send(self, summary: str, findings: list[Finding]) -> None:
        raise NotImplementedError
