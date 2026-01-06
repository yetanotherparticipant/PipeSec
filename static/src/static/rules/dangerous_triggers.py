from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class DangerousTriggersRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        on_triggers = workflow.get("on", {})
        if isinstance(on_triggers, str):
            on_triggers = {on_triggers: {}}

        if isinstance(on_triggers, dict) and "pull_request_target" in on_triggers:
            out.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="Dangerous Trigger",
                    description="Using 'pull_request_target' may lead to secret leakage from forks.",
                    location=f"{path}:on.pull_request_target",
                    recommendation=(
                        "Use 'pull_request' instead of 'pull_request_target', or add strict validation of the PR source. "
                        "Do not run untrusted code from PRs with access to secrets."
                    ),
                    fix="Replace 'pull_request_target' with 'pull_request'",
                ),
            )
        return out
