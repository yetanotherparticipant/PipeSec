from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml  # type: ignore[import-untyped]

from static.analyzers.platform import resolve_platform
from static.models import Finding, Severity
from static.rules import default_workflow_rules

if TYPE_CHECKING:
    from pathlib import Path

    from static.secrets import SecretDetectionEngine


class StaticAnalyzer:
    def __init__(
        self,
        secret_engine: SecretDetectionEngine,
        *,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
        platform: str = "auto",
    ) -> None:
        self.secret_engine = secret_engine
        self.enabled_rules = enabled_rules
        self.disabled_rules = disabled_rules
        self.requested_platform = platform
        self.resolved_platform = "github"

    @staticmethod
    def _rule_id(rule: object) -> str:
        module = getattr(rule.__class__, "__module__", "")
        return module.split(".")[-1] if isinstance(module, str) and module else ""

    @staticmethod
    def _rule_fqn(rule: object) -> str:
        module = getattr(rule.__class__, "__module__", "")
        name = getattr(rule.__class__, "__name__", "")
        if (
            not isinstance(module, str)
            or not isinstance(name, str)
            or not module
            or not name
        ):
            return ""
        return f"{module}.{name}"

    @staticmethod
    def _rule_platforms(rule: object) -> set[str]:
        value = getattr(rule, "platforms", {"github"})
        if not isinstance(value, set):
            return {"github"}
        out = {
            v.strip().lower()
            for v in value
            if isinstance(v, str) and v.strip().lower() in {"github", "gitlab"}
        }
        return out or {"github"}

    def _is_rule_enabled(self, rule: object, platform: str) -> bool:
        rule_id = self._rule_id(rule)
        rule_fqn = self._rule_fqn(rule)

        if self.enabled_rules is not None and len(self.enabled_rules) > 0:
            if rule_id not in self.enabled_rules and rule_fqn not in self.enabled_rules:
                return False

        if self.disabled_rules is not None and len(self.disabled_rules) > 0:
            if rule_id in self.disabled_rules or rule_fqn in self.disabled_rules:
                return False

        if platform not in self._rule_platforms(rule):
            return False

        return True

    def _parse_workflow(self, workflow_path: Path) -> dict[str, Any] | list[Finding]:
        try:
            workflow_text = workflow_path.read_text(encoding="utf-8")
        except Exception as exc:
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="IO Error",
                    description=f"Failed to read file: {exc}",
                    location=str(workflow_path),
                    recommendation="Check the file path and access permissions.",
                ),
            ]

        try:
            workflow = yaml.safe_load(workflow_text)
        except Exception as exc:
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="Parse Error",
                    description=f"Failed to parse YAML file: {exc}",
                    location=str(workflow_path),
                    recommendation="Check the YAML syntax.",
                ),
            ]

        if not isinstance(workflow, dict):
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="Parse Error",
                    description="YAML was parsed, but the root object is not a mapping (dictionary).",
                    location=str(workflow_path),
                    recommendation="Check the workflow format (a mapping/dictionary is expected).",
                ),
            ]
        return workflow

    def analyze_workflow_file(self, workflow_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        parsed = self._parse_workflow(workflow_path)
        if isinstance(parsed, list):
            return parsed
        workflow = parsed

        platform = resolve_platform(workflow, self.requested_platform)
        self.resolved_platform = platform

        for rule in default_workflow_rules():
            if self._is_rule_enabled(rule, platform):
                findings.extend(
                    rule.evaluate(workflow, workflow_path, self.secret_engine),
                )

        return findings
