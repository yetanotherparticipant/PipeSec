from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import iter_gitlab_jobs

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


def _contains_dind(value: Any) -> bool:
    if isinstance(value, str):
        return "docker:dind" in value.lower()
    if isinstance(value, dict):
        name = value.get("name")
        return isinstance(name, str) and "docker:dind" in name.lower()
    return False


@register_workflow_rule
class GitLabPrivilegedRunnerRule(WorkflowRule):
    platforms = {"gitlab"}

    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        for job_name, job in iter_gitlab_jobs(workflow):
            if job.get("privileged") is True:
                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Runner",
                        description="GitLab job runs with privileged=true.",
                        location=f"{path}:{job_name}.privileged",
                        recommendation="Avoid privileged jobs unless strictly required and isolate runner infrastructure.",
                    ),
                )

            services = job.get("services")
            if isinstance(services, list):
                for idx, service in enumerate(services):
                    if _contains_dind(service):
                        out.append(
                            Finding(
                                severity=Severity.HIGH,
                                category="Runner",
                                description="GitLab job uses Docker-in-Docker service.",
                                location=f"{path}:{job_name}.services[{idx}]",
                                recommendation="Avoid Docker-in-Docker on shared runners; prefer rootless/isolated build approaches.",
                            ),
                        )
                    if isinstance(service, dict) and service.get("privileged") is True:
                        out.append(
                            Finding(
                                severity=Severity.HIGH,
                                category="Runner",
                                description="GitLab service is configured with privileged=true.",
                                location=f"{path}:{job_name}.services[{idx}].privileged",
                                recommendation="Disable privileged mode for job services unless absolutely necessary.",
                            ),
                        )

            if _contains_dind(job.get("image")):
                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Runner",
                        description="GitLab job image indicates Docker-in-Docker usage.",
                        location=f"{path}:{job_name}.image",
                        recommendation="Use hardened runner images and avoid privileged Docker daemon exposure in jobs.",
                    ),
                )

        return out
