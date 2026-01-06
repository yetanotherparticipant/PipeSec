from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from _bootstrap import SRC  # noqa: F401
from static.cli import main


VULNERABLE_GITLAB = """
stages: [build]
include:
  - remote: "https://gitlab.example.com/group/-/raw/main/ci.yml"
variables:
  DEPLOY_PASSWORD: "SuperSecretPassword123456"
build:
  image: "docker:dind"
  privileged: true
  script:
    - echo "token=$CI_JOB_TOKEN"
  artifacts:
    paths:
      - .env
"""


class CLIGitLabIntegrationTests(unittest.TestCase):
    def test_cli_gitlab_platform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow = Path(tmp) / ".gitlab-ci.yml"
            workflow.write_text(VULNERABLE_GITLAB, encoding="utf-8")

            out = StringIO()
            with redirect_stdout(out):
                code = main(
                    [
                        str(workflow),
                        "--platform",
                        "gitlab",
                        "--format",
                        "json",
                    ],
                )
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            categories = {f["category"] for f in payload["findings"]}
            self.assertIn("Hardcoded Secret", categories)
            self.assertIn("Supply Chain", categories)

    def test_cli_auto_detects_gitlab(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow = Path(tmp) / ".gitlab-ci.yml"
            workflow.write_text(VULNERABLE_GITLAB, encoding="utf-8")
            out = StringIO()
            with patch.dict("os.environ", {"GITLAB_CI": "true"}, clear=False):
                with redirect_stdout(out):
                    code = main([str(workflow), "--format", "json"])
            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertGreater(payload["count"], 0)


if __name__ == "__main__":
    unittest.main()
