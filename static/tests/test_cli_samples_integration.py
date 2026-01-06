from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from _bootstrap import SRC  # noqa: F401
from static.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = PROJECT_ROOT / "samples"


class CLISamplesIntegrationTests(unittest.TestCase):
    def _run_cli(self, args: list[str]) -> tuple[int, dict]:
        output = StringIO()
        with patch.dict(
            "os.environ",
            {
                "TELEGRAM_BOT_TOKEN": "",
                "TELEGRAM_CHAT_ID": "",
                "PIPESEC_WEBHOOK_URL": "",
                "PIPESEC_WEBHOOK_HEADERS": "",
            },
            clear=False,
        ):
            with redirect_stdout(output):
                code = main(args)
        payload = json.loads(output.getvalue())
        return code, payload

    def test_safe_sample(self) -> None:
        code, payload = self._run_cli(
            [str(SAMPLES_DIR / "safe-all.yml"), "--format", "json"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["count"], 0)

    def test_vulnerable_sample(self) -> None:
        code, payload = self._run_cli(
            [str(SAMPLES_DIR / "vulnerable-all.yml"), "--format", "json"],
        )
        self.assertEqual(code, 1)
        self.assertGreater(payload["count"], 0)
        self.assertGreater(payload["countsBySeverity"]["CRITICAL"], 0)

    def test_vulnerable_plus_log_increases_critical_findings(self) -> None:
        _, base = self._run_cli(
            [str(SAMPLES_DIR / "vulnerable-all.yml"), "--format", "json"],
        )
        _, with_log = self._run_cli(
            [
                str(SAMPLES_DIR / "vulnerable-all.yml"),
                "--format",
                "json",
                "--log",
                str(SAMPLES_DIR / "build.log"),
            ],
        )

        self.assertGreater(with_log["count"], base["count"])
        self.assertGreater(
            with_log["countsBySeverity"]["CRITICAL"],
            base["countsBySeverity"]["CRITICAL"],
        )

    def test_fix_mode_exposes_fix_suggestions(self) -> None:
        code, payload = self._run_cli(
            [str(SAMPLES_DIR / "vulnerable-all.yml"), "--format", "json", "--fix"],
        )
        self.assertEqual(code, 1)
        self.assertTrue(
            any(finding.get("fix") for finding in payload["findings"]),
        )


if __name__ == "__main__":
    unittest.main()
