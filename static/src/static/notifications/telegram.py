from __future__ import annotations

import json
import urllib.request
from typing import TYPE_CHECKING

from .base import NotificationChannel

if TYPE_CHECKING:
    from static.models import Finding


class TelegramChannel(NotificationChannel):
    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = chat_id

    def send(self, summary: str, findings: list[Finding]) -> None:
        if not self.token or not self.chat_id:
            return
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            data = {"chat_id": self.chat_id, "text": summary, "parse_mode": "Markdown"}
            encoded_data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=encoded_data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            pass
