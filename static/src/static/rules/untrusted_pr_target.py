from __future__ import annotations

from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import (
    get_run,
    get_step_name,
    iter_jobs,
    iter_steps,
    run_has_local_exec,
)

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class UntrustedCodeOnPRTargetRule(WorkflowRule):
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

        if not (isinstance(on_triggers, dict) and "pull_request_target" in on_triggers):
            return out

        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                run = get_run(step)
                if not isinstance(run, str):
                    continue
                if not run_has_local_exec(run):
                    continue

                step_name = get_step_name(step, idx)
                out.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="Untrusted Code Execution",
                        description=(
                            f"In step '{step_name}', a local script/file is executed under the 'pull_request_target' trigger. "
                            "This can allow a PR author to run arbitrary code with access to secrets."
                        ),
                        location=f"{path}:jobs.{job_name}.steps[{idx}]",
                        recommendation=(
                            "Do not execute PR code under pull_request_target. Use pull_request instead, or split the workflow: "
                            "run safe checks for PRs without secrets, and run deploy/secrets only after merge/approval."
                        ),
                    ),
                )

        return out
