from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from _bootstrap import SRC  # noqa: F401
from static.analyzers.platform import resolve_platform


class PlatformDetectionTests(unittest.TestCase):
    def test_env_precedence_over_yaml(self) -> None:
        workflow = {"stages": ["build"], "jobs": {"build": {"runs-on": "ubuntu-latest"}}}
        with patch.dict(
            os.environ,
            {"GITHUB_ACTIONS": "true", "GITLAB_CI": "true"},
            clear=False,
        ):
            self.assertEqual(resolve_platform(workflow, "auto"), "github")

    def test_yaml_github_detection(self) -> None:
        workflow = {"jobs": {"build": {"runs-on": "ubuntu-latest"}}}
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GITLAB_CI": ""}, clear=False):
            self.assertEqual(resolve_platform(workflow, "auto"), "github")

    def test_yaml_gitlab_detection(self) -> None:
        workflow = {"stages": ["build"], "build": {"script": ["echo test"]}}
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GITLAB_CI": ""}, clear=False):
            self.assertEqual(resolve_platform(workflow, "auto"), "gitlab")

    def test_forced_platform(self) -> None:
        workflow = {"jobs": {"build": {"runs-on": "ubuntu-latest"}}}
        self.assertEqual(resolve_platform(workflow, "gitlab"), "gitlab")


if __name__ == "__main__":
    unittest.main()
