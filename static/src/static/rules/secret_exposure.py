from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import get_step_name, iter_jobs, iter_steps

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SecretExposureRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                run_command = step.get("run", "")
                if isinstance(run_command, str) and re.search(
                    r"(echo|print).*(\$\{\{\s*secrets\.|\$\{\{\s*github\.token\s*\}\})",
                    run_command,
                    re.IGNORECASE,
                ):
                    step_name = get_step_name(step, idx)
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Secret Exposure",
                            description=f"A secret may be printed to logs via echo/print in step '{step_name}'.",
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation="Do not print secrets/tokens to stdout. If debugging is required, use masking and redaction.",
                        ),
                    )

                uses_value = step.get("uses", "")
                if isinstance(uses_value, str) and uses_value.startswith(
                    "actions/upload-artifact",
                ):
                    with_config = step.get("with", {})
                    if isinstance(with_config, dict):
                        upload_path = str(with_config.get("path", ""))
                        if any(
                            k in upload_path.lower()
                            for k in ["env", "secret", ".env", "credential"]
                        ):
                            out.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    category="Artifact Exposure",
                                    description=f"An artifact may contain secrets: '{upload_path}'.",
                                    location=f"{path}:jobs.{job_name}.steps[{idx}]",
                                    recommendation="Exclude .env/credentials/secrets from artifacts (artifact exclude / separate paths).",
                                ),
                            )

        return out
