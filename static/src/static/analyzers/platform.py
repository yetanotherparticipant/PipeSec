from __future__ import annotations

import os
from typing import Any

PLATFORMS = {"github", "gitlab", "auto"}


def resolve_platform(workflow: dict[str, Any], requested: str = "auto") -> str:
    if requested in {"github", "gitlab"}:
        return requested

    env_github = os.environ.get("GITHUB_ACTIONS", "").strip().lower()
    env_gitlab = os.environ.get("GITLAB_CI", "").strip().lower()
    if env_github == "true":
        return "github"
    if env_gitlab == "true":
        return "gitlab"

    if _looks_like_github(workflow):
        return "github"
    if _looks_like_gitlab(workflow):
        return "gitlab"
    return "github"


def _looks_like_github(workflow: dict[str, Any]) -> bool:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if isinstance(job, dict) and "runs-on" in job:
            return True
    return False


def _looks_like_gitlab(workflow: dict[str, Any]) -> bool:
    if "stages" in workflow or "image" in workflow:
        return True

    if isinstance(workflow.get("script"), (str, list)):
        return True

    reserved = {
        "stages",
        "image",
        "variables",
        "include",
        "default",
        "workflow",
        "before_script",
        "after_script",
        "cache",
        "services",
    }
    for key, value in workflow.items():
        if not isinstance(key, str) or key.startswith(".") or key in reserved:
            continue
        if isinstance(value, dict) and isinstance(value.get("script"), (str, list)):
            return True
    return False
