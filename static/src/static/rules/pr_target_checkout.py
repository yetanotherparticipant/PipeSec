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
class PRTargetUntrustedCheckoutRule(WorkflowRule):
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
                uses = get_uses(step)
                if not isinstance(uses, str):
                    continue
                if not uses.startswith("actions/checkout"):
                    continue

                with_cfg = step.get("with", {})
                if not isinstance(with_cfg, dict):
                    continue

                ref = with_cfg.get("ref")
                if not isinstance(ref, str):
                    continue

                lower = ref.lower()
                if (
                    "github.event.pull_request.head" in lower
                    or "github.head_ref" in lower
                    or "pull_request.head" in lower
                ):
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Untrusted Code Execution",
                            description=(
                                "In a workflow triggered by 'pull_request_target', the job checks out the PR head ref/sha. "
                                "This is a common path to executing fork code with access to secrets."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}].with.ref",
                            recommendation=(
                                "Do not check out PR code in a workflow triggered by pull_request_target. "
                                "Use pull_request instead, or split the workflow: run PR checks without secrets, "
                                "and run deploy/secrets only after merge/approval."
                            ),
                            evidence=ref,
                        ),
                    )
        return out
