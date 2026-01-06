from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from _bootstrap import SRC  # noqa: F401
from static.analyzers.static_analyzer import StaticAnalyzer
from static.analyzers.static_github_actions import StaticGithubActionsAnalyzer
from static.secrets import SecretDetectionEngine


class AnalyzerPlatformFilterTests(unittest.TestCase):
    def test_alias_is_compatible(self) -> None:
        self.assertIs(StaticGithubActionsAnalyzer, StaticAnalyzer)

    def test_github_rule_not_applied_in_gitlab_mode(self) -> None:
        workflow_text = """
stages: [build]
on:
  pull_request_target: {}
variables:
  DEPLOY_PASSWORD: "SuperSecretPassword123456"
build:
  script:
    - echo test
"""
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / ".gitlab-ci.yml"
            wf.write_text(workflow_text, encoding="utf-8")

            analyzer = StaticAnalyzer(
                SecretDetectionEngine(),
                platform="gitlab",
            )
            findings = analyzer.analyze_workflow_file(wf)
            categories = {f.category for f in findings}
            self.assertNotIn("Dangerous Trigger", categories)
            self.assertIn("Hardcoded Secret", categories)

    def test_auto_platform_uses_env_precedence(self) -> None:
        workflow_text = """
stages: [build]
build:
  script:
    - echo "$CI_JOB_TOKEN"
"""
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / ".gitlab-ci.yml"
            wf.write_text(workflow_text, encoding="utf-8")
            with patch.dict(os.environ, {"GITLAB_CI": "true"}, clear=False):
                analyzer = StaticAnalyzer(SecretDetectionEngine(), platform="auto")
                analyzer.analyze_workflow_file(wf)
                self.assertEqual(analyzer.resolved_platform, "gitlab")


if __name__ == "__main__":
    unittest.main()
