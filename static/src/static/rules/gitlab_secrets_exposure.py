from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import (
    get_gitlab_variables,
    iter_gitlab_jobs,
    iter_gitlab_scripts,
)

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class GitLabSecretsExposureRule(WorkflowRule):
    platforms = {"gitlab"}

    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        def check_variables(vars_map: dict[str, str], location: str) -> None:
            for key, value in vars_map.items():
                if not value.strip():
                    continue
                if value.strip().startswith("$"):
                    continue
                secret_matches = secret_engine.detect_in_text(value)
                if secret_matches or secret_engine.is_suspicious_env_name(key):
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Hardcoded Secret",
                            description=f"Possible hardcoded secret in GitLab CI variable '{key}'.",
                            location=location,
                            recommendation="Move secrets to protected/masked GitLab CI variables and avoid hardcoded literals in .gitlab-ci.yml.",
                            evidence=(value[:20] + "...") if len(value) > 20 else value,
                        ),
                    )

        check_variables(get_gitlab_variables(workflow), f"{path}:variables")

        ci_token_exposure = re.compile(
            r"(?i)\b(echo|printf|print)\b[^\n]*\$CI_JOB_TOKEN\b",
        )
        ci_token_script_use = re.compile(r"(?i)\$CI_JOB_TOKEN")

        for job_name, job in iter_gitlab_jobs(workflow):
            check_variables(
                get_gitlab_variables(job),
                f"{path}:{job_name}.variables",
            )

            for script_location, line in iter_gitlab_scripts(workflow, job_name, job):
                if ci_token_exposure.search(line):
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Secret Exposure",
                            description="CI_JOB_TOKEN may be printed to logs in GitLab CI script.",
                            location=f"{path}:{script_location}",
                            recommendation="Do not print CI_JOB_TOKEN or other secrets; use masked variables and secure logging practices.",
                            evidence=(line[:80] + "...") if len(line) > 80 else line,
                        ),
                    )
                    continue
                if ci_token_script_use.search(line) and "curl" in line.lower():
                    out.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="Secret Exposure",
                            description="CI_JOB_TOKEN is used in a shell command and may be exposed in process args/logs.",
                            location=f"{path}:{script_location}",
                            recommendation="Use protected variables and avoid passing CI_JOB_TOKEN directly in command arguments.",
                            evidence=(line[:80] + "...") if len(line) > 80 else line,
                        ),
                    )

        return out
