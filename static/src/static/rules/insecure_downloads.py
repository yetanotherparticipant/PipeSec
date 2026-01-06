from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import get_run, get_step_name, iter_jobs, iter_steps

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class InsecureDownloadsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        pipe_exec = re.compile(
            r"(?i)\b(curl|wget)\b[^\n]*\|\s*(bash|sh|zsh|python|python3)\b",
        )

        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                run = get_run(step)
                if not isinstance(run, str):
                    continue
                if pipe_exec.search(run):
                    step_name = get_step_name(step, idx)
                    out.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="Supply Chain",
                            description=(
                                f"In step '{step_name}', a potentially unsafe download-and-execute pattern was detected: curl/wget | shell."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation=(
                                "Avoid curl|bash. Download the artifact over HTTPS, verify the checksum/signature, and execute it locally. "
                                "Prefer pinned versions and trusted sources."
                            ),
                        ),
                    )

        return out
