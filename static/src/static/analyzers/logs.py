from __future__ import annotations

from typing import TYPE_CHECKING

from static.models import Finding, Severity

if TYPE_CHECKING:
    from static.secrets import SecretDetectionEngine


class LogAnalyzer:
    def __init__(self, secret_engine: SecretDetectionEngine) -> None:
        self.secret_engine = secret_engine

    def analyze_text(
        self,
        log_content: str,
        log_source: str = "workflow.log",
    ) -> list[Finding]:
        findings: list[Finding] = []

        matches = self.secret_engine.detect_in_text(log_content)
        if not matches:
            return findings

        lines = log_content.splitlines()
        for secret in matches:
            line_num = 0
            for i, line in enumerate(lines, 1):
                if secret.value in line:
                    line_num = i
                    break

            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="Secret in Logs",
                    description=f"Detected a secret of type '{secret.secret_type}' in execution logs.",
                    location=f"{log_source}:line {line_num}"
                    if line_num
                    else log_source,
                    recommendation="A secret was written to the logs: rotate it immediately and fix the step that prints it.",
                    evidence=(secret.value[:20] + "...")
                    if len(secret.value) > 20
                    else secret.value,
                ),
            )

        return findings
