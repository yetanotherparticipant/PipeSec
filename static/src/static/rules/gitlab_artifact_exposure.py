from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import iter_gitlab_jobs, normalize_script

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


SUSPICIOUS_ARTIFACT_RE = re.compile(r"(?i)(^|/)(\.env|.*\.key|.*\.pem|.*credentials?.*|.*secret.*)$")


@register_workflow_rule
class GitLabArtifactExposureRule(WorkflowRule):
    platforms = {"gitlab"}

    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        for job_name, job in iter_gitlab_jobs(workflow):
            artifacts = job.get("artifacts")
            if not isinstance(artifacts, dict):
                continue

            paths = normalize_script(artifacts.get("paths"))
            for idx, artifact_path in enumerate(paths):
                if SUSPICIOUS_ARTIFACT_RE.search(artifact_path.strip()):
                    out.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="Artifact Exposure",
                            description="GitLab artifact path may include secrets or credentials.",
                            location=f"{path}:{job_name}.artifacts.paths[{idx}]",
                            recommendation="Exclude secret files from artifacts and keep credentials outside artifact paths.",
                            evidence=artifact_path,
                        ),
                    )

        return out
