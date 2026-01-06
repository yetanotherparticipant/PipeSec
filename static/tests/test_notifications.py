from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from _bootstrap import SRC  # noqa: F401
from static.models import Finding, Severity
from static.notifications.registry import channels_from_env
from static.notifications.webhook import WebhookChannel


class _DummyResponse:
    def __enter__(self) -> "_DummyResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class NotificationsTests(unittest.TestCase):
    def test_channels_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "TELEGRAM_BOT_TOKEN": "t",
                "TELEGRAM_CHAT_ID": "c",
                "PIPESEC_WEBHOOK_URL": "https://example.test/webhook",
                "PIPESEC_WEBHOOK_HEADERS": '{"X-Test":"1"}',
            },
            clear=False,
        ):
            channels = channels_from_env()
            self.assertEqual(len(channels), 2)

    def test_webhook_payload(self) -> None:
        finding = Finding(
            severity=Severity.HIGH,
            category="Test",
            description="desc",
            location="loc",
            recommendation="rec",
        )
        channel = WebhookChannel("https://example.test/webhook", {"X-Token": "abc"})

        with patch("urllib.request.urlopen", return_value=_DummyResponse()) as urlopen:
            channel.send("summary", [finding])
            self.assertTrue(urlopen.called)
            request = urlopen.call_args.args[0]
            payload = json.loads(request.data.decode("utf-8"))
            self.assertEqual(payload["summary"], "summary")
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["findings"][0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
