from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import iter_jobs

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SelfHostedRunnerRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            runs_on = job_config.get("runs-on")

            labels: list[str] = []
            if isinstance(runs_on, str):
                labels = [runs_on]
            elif isinstance(runs_on, list):
                labels = [x for x in runs_on if isinstance(x, str)]

            if any(lbl.lower().strip() == "self-hosted" for lbl in labels):
                out.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="Runner",
                        description=f"Job '{job_name}' uses a self-hosted runner.",
                        location=f"{path}:jobs.{job_name}.runs-on",
                        recommendation=(
                            "Self-hosted runners increase risk (persistent environment, possible leftovers of secrets/artifacts). "
                            "Strengthen hardening, isolation, workspace cleanup, egress control, and minimize permissions."
                        ),
                    ),
                )

        return out
