from __future__ import annotations

import unittest
from pathlib import Path

from _bootstrap import SRC  # noqa: F401
from static.rules.gitlab_artifact_exposure import GitLabArtifactExposureRule
from static.rules.gitlab_insecure_includes import GitLabInsecureIncludesRule
from static.rules.gitlab_privileged_runner import GitLabPrivilegedRunnerRule
from static.rules.gitlab_secrets_exposure import GitLabSecretsExposureRule
from static.secrets import SecretDetectionEngine


class GitLabRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = SecretDetectionEngine()
        self.path = Path(".gitlab-ci.yml")

    def test_gitlab_secrets_exposure_rule(self) -> None:
        workflow = {
            "variables": {"DEPLOY_PASSWORD": "SuperSecretPassword123456"},
            "build": {"script": ['echo "token=$CI_JOB_TOKEN"']},
        }
        findings = GitLabSecretsExposureRule().evaluate(workflow, self.path, self.engine)
        categories = {f.category for f in findings}
        self.assertIn("Hardcoded Secret", categories)
        self.assertIn("Secret Exposure", categories)

    def test_gitlab_insecure_includes_rule(self) -> None:
        workflow = {
            "include": [
                {"remote": "https://gitlab.example.com/group/-/raw/main/ci.yml"},
                {"project": "group/templates", "file": "/base.yml"},
            ],
        }
        findings = GitLabInsecureIncludesRule().evaluate(workflow, self.path, self.engine)
        self.assertGreaterEqual(len(findings), 2)

    def test_gitlab_privileged_runner_rule(self) -> None:
        workflow = {
            "build": {
                "privileged": True,
                "services": [{"name": "docker:dind", "privileged": True}],
                "image": "docker:dind",
            },
        }
        findings = GitLabPrivilegedRunnerRule().evaluate(workflow, self.path, self.engine)
        self.assertGreaterEqual(len(findings), 3)

    def test_gitlab_artifact_exposure_rule(self) -> None:
        workflow = {
            "build": {
                "artifacts": {"paths": ["dist/", ".env", "keys/deploy.key"]},
            },
        }
        findings = GitLabArtifactExposureRule().evaluate(workflow, self.path, self.engine)
        self.assertGreaterEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
