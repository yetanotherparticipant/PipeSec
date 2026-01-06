from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import get_uses, iter_jobs, iter_steps

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class UnpinnedActionsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                uses_value = get_uses(step)
                if not isinstance(uses_value, str) or "@" not in uses_value:
                    continue

                _, ref = uses_value.rsplit("@", 1)
                if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    continue

                out.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="Unpinned Action",
                        description=f"Action '{uses_value}' is not pinned to a commit SHA (a tag/branch is used).",
                        location=f"{path}:jobs.{job_name}.steps[{idx}].uses",
                        recommendation="To reduce supply-chain risk, pin actions by SHA (for example: actions/checkout@<sha>).",
                    ),
                )

        return out
