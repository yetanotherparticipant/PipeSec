from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml  # type: ignore[import-untyped]

from static.models import Finding, Severity
from static.rules.base import WorkflowRule

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class HardcodedSecretsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        yaml_str = yaml.dump(workflow, sort_keys=False)
        for secret in secret_engine.detect_in_text(yaml_str):
            if "${{" in secret.value or "secrets." in secret.value:
                continue
            out.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="Hardcoded Secret",
                    description=f"Hardcoded secret detected (type: '{secret.secret_type}').",
                    location=str(path),
                    recommendation="Move the secret to GitHub Secrets/Variables and reference it via ${{ secrets.NAME }}.",
                    evidence=(secret.value[:20] + "...")
                    if len(secret.value) > 20
                    else secret.value,
                ),
            )
        return out
