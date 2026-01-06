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
class DockerImagePinningRule(WorkflowRule):
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

                if not uses.startswith("docker://"):
                    continue

                image = uses[len("docker://") :]
                if "@sha256:" in image:
                    continue

                if ":" not in image or image.endswith(":latest"):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Supply Chain",
                            description="A docker image is used without pinning to a digest (or it uses :latest).",
                            location=f"{path}:jobs.{job_name}.steps[{idx}].uses",
                            recommendation=(
                                "Pin the docker image by digest (docker://image@sha256:...) or use a fixed tag. "
                                "This reduces the risk of supply-chain tampering."
                            ),
                            evidence=uses,
                        ),
                    )

        return out
