from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


def _check_permissions_obj(permissions: Any) -> bool:
    if not isinstance(permissions, dict):
        return False
    v = permissions.get("id-token")
    return isinstance(v, str) and v.strip().lower() == "write"


@register_workflow_rule
class OIDCPermissionsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        if _check_permissions_obj(workflow.get("permissions")):
            out.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="Permissions",
                    description="Workflow requests 'id-token: write' (OIDC).",
                    location=f"{path}:permissions.id-token",
                    recommendation=(
                        "Use 'id-token: write' only when necessary (OIDC federation). "
                        "Make sure trusted audiences/providers are configured strictly and minimize other permissions."
                    ),
                ),
            )

        jobs = workflow.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_config in jobs.items():
                if not isinstance(job_config, dict):
                    continue
                if _check_permissions_obj(job_config.get("permissions")):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Permissions",
                            description=f"Job '{job_name}' requests 'id-token: write' (OIDC).",
                            location=f"{path}:jobs.{job_name}.permissions.id-token",
                            recommendation=(
                                "Request the OIDC token only in the job that uses it, and only for as long as needed."
                            ),
                        ),
                    )

        return out
