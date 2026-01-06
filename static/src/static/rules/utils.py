from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


def iter_jobs(workflow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job_config in jobs.items():
        if isinstance(job_name, str) and isinstance(job_config, dict):
            yield job_name, job_config


def iter_steps(job_config: dict[str, Any]) -> Iterator[tuple[int, dict[str, Any]]]:
    steps = job_config.get("steps", [])
    if not isinstance(steps, list):
        return
    for idx, step in enumerate(steps):
        if isinstance(step, dict):
            yield idx, step


def get_step_name(step: dict[str, Any], idx: int) -> str:
    name = step.get("name")
    return name if isinstance(name, str) and name.strip() else f"step-{idx}"


def get_run(step: dict[str, Any]) -> str | None:
    v = step.get("run")
    return v if isinstance(v, str) else None


def get_uses(step: dict[str, Any]) -> str | None:
    v = step.get("uses")
    return v if isinstance(v, str) else None


def get_env(obj: dict[str, Any]) -> dict[str, str]:
    env = obj.get("env", {})
    if not isinstance(env, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in env.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out


def is_expression(value: str) -> bool:
    return "${{" in value


def contains_secret_context(value: str) -> bool:
    v = value.lower()
    return "secrets." in v or "github.token" in v


def run_has_local_exec(run: str) -> bool:
    return bool(re.search(r"(?m)^\s*(chmod\s+\+x\s+\./|\./)", run))


GITLAB_RESERVED_TOP_LEVEL_KEYS = {
    "stages",
    "variables",
    "include",
    "default",
    "workflow",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
}


def normalize_script(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def iter_gitlab_jobs(workflow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for key, value in workflow.items():
        if (
            isinstance(key, str)
            and isinstance(value, dict)
            and key not in GITLAB_RESERVED_TOP_LEVEL_KEYS
            and not key.startswith(".")
        ):
            yield key, value


def iter_gitlab_scripts(
    workflow: dict[str, Any],
    job_name: str,
    job: dict[str, Any],
) -> Iterator[tuple[str, str]]:
    for idx, line in enumerate(normalize_script(workflow.get("before_script"))):
        yield (f"{job_name}:before_script[{idx}]", line)
    for idx, line in enumerate(normalize_script(job.get("before_script"))):
        yield (f"{job_name}:job.before_script[{idx}]", line)
    for idx, line in enumerate(normalize_script(job.get("script"))):
        yield (f"{job_name}:script[{idx}]", line)
    for idx, line in enumerate(normalize_script(job.get("after_script"))):
        yield (f"{job_name}:after_script[{idx}]", line)


def get_gitlab_variables(obj: dict[str, Any]) -> dict[str, str]:
    raw = obj.get("variables")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out
