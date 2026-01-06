from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import (
    contains_secret_context,
    get_env,
    get_uses,
    is_expression,
    iter_jobs,
    iter_steps,
)

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


def _dict_values_strings(d: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for v in d.values():
        if isinstance(v, str):
            out.append(v)
    return out


@register_workflow_rule
class ThirdPartyActionSecretsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                uses = get_uses(step)
                if not isinstance(uses, str) or "@" not in uses:
                    continue

                action, _ref = uses.rsplit("@", 1)
                if action.startswith("actions/"):
                    continue

                env_values = list(get_env(step).values())
                with_cfg = step.get("with", {})
                with_values: list[str] = (
                    _dict_values_strings(with_cfg) if isinstance(with_cfg, dict) else []
                )

                passed = [
                    v
                    for v in (env_values + with_values)
                    if isinstance(v, str)
                    and (is_expression(v) or contains_secret_context(v))
                ]
                if not passed:
                    continue

                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Third-Party Action",
                        description="Secrets/tokens are being passed to a third-party GitHub Action.",
                        location=f"{path}:jobs.{job_name}.steps[{idx}]",
                        recommendation=(
                            "Minimize passing secrets to third-party actions. Prefer official actions, "
                            "verify reputation/signatures, pin by SHA, and use a separate token with minimal permissions."
                        ),
                        evidence=uses,
                    ),
                )

        return out
