from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from static.rules.utils import get_env, get_run, get_step_name, iter_jobs, iter_steps

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


@register_workflow_rule
class DebugTracingRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        wf_env = get_env(workflow)
        for key in ("ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"):
            v = wf_env.get(key)
            if isinstance(v, str) and v.strip().lower() in {"1", "true", "yes", "on"}:
                out.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="Logging",
                        description=f"Debug mode is enabled via env '{key}={v}'.",
                        location=f"{path}:env.{key}",
                        recommendation=(
                            "Disable debug logging in production CI to reduce the risk of leaking sensitive data into logs."
                        ),
                    ),
                )

        for job_name, job_config in iter_jobs(workflow):
            job_env = get_env(job_config)
            for key in ("ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG"):
                v = job_env.get(key)
                if isinstance(v, str) and v.strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "on",
                }:
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Logging",
                            description=f"Debug mode is enabled via env '{key}={v}' in job '{job_name}'.",
                            location=f"{path}:jobs.{job_name}.env.{key}",
                            recommendation=(
                                "Disable debug logging in production CI to reduce the risk of leaking sensitive data into logs."
                            ),
                        ),
                    )

            for idx, step in iter_steps(job_config):
                run = get_run(step)
                if not isinstance(run, str):
                    continue

                if re.search(r"(?m)^\s*set\s+-x\b", run) or re.search(
                    r"\b(bash|sh)\s+-x\b",
                    run,
                ):
                    step_name = get_step_name(step, idx)
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Logging",
                            description=f"Shell tracing is enabled in step '{step_name}' (set -x / bash -x).",
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation=(
                                "Do not use set -x / bash -x in CI when secrets are present: commands and variable values can end up in logs."
                            ),
                        ),
                    )

        return out
