from __future__ import annotations

from collections import defaultdict

from static.models import Finding, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def render_console_report(findings: list[Finding], show_fix: bool = False) -> str:
    if not findings:
        return "No vulnerabilities found!"

    by_severity: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_severity[finding.severity.value].append(finding)

    lines: list[str] = []
    lines.append("\n" + "=" * 80)
    lines.append("PipeSec Static - Report")
    lines.append("=" * 80 + "\n")

    lines.append(f"Total issues found: {len(findings)}")
    for sev in _SEVERITY_ORDER:
        cnt = len(by_severity.get(sev.value, []))
        if cnt:
            lines.append(f"   {sev.value}: {cnt}")

    lines.append("")

    for sev in _SEVERITY_ORDER:
        group = by_severity.get(sev.value, [])
        if not group:
            continue
        lines.append(f"{sev.value} ({len(group)})")
        for i, f in enumerate(group, 1):
            lines.append(f"  {i}. [{f.category}] {f.description}")
            lines.append(f"     Location: {f.location}")
            lines.append(f"     Recommendation: {f.recommendation}")
            if f.evidence:
                lines.append(f"     Evidence: {f.evidence}")
            if show_fix and f.fix:
                lines.append(f"     Fix: {f.fix}")
            lines.append("")

    return "\n".join(lines)
