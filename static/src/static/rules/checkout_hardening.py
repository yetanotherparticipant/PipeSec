from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import get_uses, iter_jobs, iter_steps

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class CheckoutCredentialPersistenceRule(WorkflowRule):
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
                if not isinstance(uses, str):
                    continue
                if not uses.startswith("actions/checkout"):
                    continue

                with_cfg = step.get("with", {})
                if not isinstance(with_cfg, dict):
                    with_cfg = {}

                pc = with_cfg.get("persist-credentials")
                if pc is None or (
                    isinstance(pc, str)
                    and pc.strip().lower() in {"true", "1", "yes", "on"}
                ):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Checkout Hardening",
                            description=(
                                "actions/checkout is executed with persist-credentials=true (explicitly or by default). "
                                "This leaves the token in the git config and increases the risk of abuse when running untrusted code."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation=(
                                "Set `with: persist-credentials: false` for actions/checkout if a push is not required. "
                                "Also minimize GITHUB_TOKEN permissions."
                            ),
                        ),
                    )

        return out
