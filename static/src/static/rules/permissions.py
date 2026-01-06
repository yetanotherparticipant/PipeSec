from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class ExcessivePermissionsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        permissions = workflow.get("permissions")
        if permissions is None:
            out.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="Permissions",
                    description="The workflow does not set explicit permissions for GITHUB_TOKEN.",
                    location=f"{path}:permissions",
                    recommendation=(
                        "Explicitly set the minimum required permissions (principle of least privilege). "
                        "This reduces the risk of privilege escalation if the runner/Action is compromised."
                    ),
                ),
            )
            return out

        if permissions == "write-all":
            out.append(
                Finding(
                    severity=Severity.HIGH,
                    category="Excessive Permissions",
                    description="The workflow has 'write-all' permissions.",
                    location=f"{path}:permissions",
                    recommendation="Use the principle of least privilege: specify only the permissions you need.",
                ),
            )

        if isinstance(permissions, dict):
            risky = {
                "contents",
                "packages",
                "actions",
                "pull-requests",
                "issues",
                "deployments",
            }
            for k, v in permissions.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    continue
                if k in risky and v.lower().strip() == "write":
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Permissions",
                            description=f"The workflow requests elevated privileges: '{k}: write'.",
                            location=f"{path}:permissions.{k}",
                            recommendation="Verify whether write access is necessary and minimize permissions wherever possible.",
                        ),
                    )
        return out
