from __future__ import annotations

import json
import urllib.request
from dataclasses import asdict
from typing import TYPE_CHECKING

from .base import NotificationChannel

if TYPE_CHECKING:
    from static.models import Finding


def _serialize_finding(finding: Finding) -> dict[str, object]:
    data = asdict(finding)
    sev = data.get("severity")
    if hasattr(sev, "value"):
        data["severity"] = getattr(sev, "value")
    return data


class WebhookChannel(NotificationChannel):
    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = dict(headers or {})

    def send(self, summary: str, findings: list[Finding]) -> None:
        if not self.url:
            return
        payload = {
            "summary": summary,
            "findings": [_serialize_finding(f) for f in findings],
            "count": len(findings),
        }
        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    **self.headers,
                },
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            pass
