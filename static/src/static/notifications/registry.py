from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from .base import NotificationChannel
from .telegram import TelegramChannel
from .webhook import WebhookChannel

if TYPE_CHECKING:
    from collections.abc import Mapping


def _parse_headers_json(raw: str) -> Mapping[str, str]:
    try:
        value = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in value.items():
        if isinstance(k, str) and isinstance(v, str) and k.strip():
            out[k] = v
    return out


def channels_from_env() -> list[NotificationChannel]:
    channels: list[NotificationChannel] = []

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if tg_token and tg_chat:
        channels.append(TelegramChannel(tg_token, tg_chat))

    webhook_url = os.environ.get("PIPESEC_WEBHOOK_URL", "").strip()
    if webhook_url:
        headers_raw = os.environ.get("PIPESEC_WEBHOOK_HEADERS", "").strip()
        headers = _parse_headers_json(headers_raw) if headers_raw else {}
        channels.append(WebhookChannel(webhook_url, dict(headers)))

    return channels
