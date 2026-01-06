from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule

from .registry import register_workflow_rule

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


def _normalize_include(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return []


def _remote_is_pinned(url: str) -> bool:
    sha_param = re.search(r"(?i)(?:\?|&)(?:ref|sha)=([0-9a-f]{40}|[0-9a-f]{64})\b", url)
    if sha_param:
        return True
    raw_path_sha = re.search(r"/raw/[0-9a-f]{40,64}/", url)
    return bool(raw_path_sha)


@register_workflow_rule
class GitLabInsecureIncludesRule(WorkflowRule):
    platforms = {"gitlab"}

    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        for idx, include in enumerate(_normalize_include(workflow.get("include"))):
            remote = include.get("remote")
            if isinstance(remote, str) and remote.startswith(("http://", "https://")):
                if not _remote_is_pinned(remote):
                    out.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="Supply Chain",
                            description="GitLab remote include is not pinned to an immutable ref/SHA.",
                            location=f"{path}:include[{idx}].remote",
                            recommendation="Pin remote includes to immutable commit SHA and avoid mutable refs.",
                            evidence=remote,
                        ),
                    )

            if "project" in include and "file" in include and "ref" not in include:
                out.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="Supply Chain",
                        description="GitLab project include does not specify a fixed ref.",
                        location=f"{path}:include[{idx}]",
                        recommendation="Set `ref` to an immutable commit/tag for included project templates.",
                    ),
                )

        return out
