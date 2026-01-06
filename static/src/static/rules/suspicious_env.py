from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import (
    contains_secret_context,
    get_env,
    is_expression,
    iter_jobs,
    iter_steps,
)

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SuspiciousEnvRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        def check_env(env: dict[str, str], location: str) -> None:
            for k, v in env.items():
                if not secret_engine.is_suspicious_env_name(k):
                    continue
                if not isinstance(v, str) or not v.strip():
                    continue
                if is_expression(v) or contains_secret_context(v):
                    continue
                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Hardcoded Secret",
                        description=(
                            f"Suspicious environment variable '{k}' has a literal value (possible hardcoded secret)."
                        ),
                        location=location,
                        recommendation="Move the value to GitHub Secrets/Variables and reference it via ${{ secrets.NAME }}.",
                        evidence=(v[:20] + "...") if len(v) > 20 else v,
                    ),
                )

        check_env(get_env(workflow), f"{path}:env")

        for job_name, job_config in iter_jobs(workflow):
            check_env(get_env(job_config), f"{path}:jobs.{job_name}.env")
            for idx, step in iter_steps(job_config):
                check_env(get_env(step), f"{path}:jobs.{job_name}.steps[{idx}].env")

        return out
