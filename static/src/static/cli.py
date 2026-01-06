from __future__ import annotations

import argparse
import sys
from pathlib import Path

from static.analyzers.logs import LogAnalyzer
from static.analyzers.static_analyzer import StaticAnalyzer
from static.models import Finding, Severity
from static.notifications import channels_from_env
from static.reporting.console import render_console_report
from static.reporting.json_report import render_json
from static.rules.registry import default_workflow_rules
from static.secrets import SecretDetectionEngine


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity_value(severity: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }.get(severity, 0)


def _max_severity(findings: list[Finding]) -> int:
    max_sev = 0
    for finding in findings:
        max_sev = max(max_sev, _severity_value(finding.severity))
    return max_sev


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipesec",
        description="PipeSec: CI/CD security scanner",
        epilog="""\
Environment variables:
- TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID for Telegram alerts
- PIPESEC_WEBHOOK_URL, PIPESEC_WEBHOOK_HEADERS for generic webhook alerts
""",
    )

    parser.add_argument(
        "workflow",
        type=Path,
        nargs="?",
        help="Path to workflow YAML (.github/workflows/* or .gitlab-ci.yml)",
    )
    parser.add_argument(
        "--platform",
        choices=["github", "gitlab", "auto"],
        default="auto",
        help="Workflow platform mode (default: auto)",
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        type=Path,
        default=None,
        help="Path to log (optional)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Return exit code 1 when there is finding with severity >= this value",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Suggest fixes",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Report format",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        type=Path,
        default=None,
        help="Output report to file instead of stdout",
    )
    parser.add_argument(
        "--patterns",
        dest="patterns_path",
        type=Path,
        default=None,
        help=(
            "Path to JSON with RegEx patterns (optional). "
            "By default using data/secret_patterns.json, if it is present."
        ),
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Output list of existing rules",
    )
    parser.add_argument(
        "--enable-rule",
        dest="enable_rules",
        action="append",
        default=[],
        help=(
            "Enable only listed rules (repeatable). "
            "Value: rule id (example: dangerous_triggers) or full class name "
            "(example: static.rules.dangerous_triggers.DangerousTriggersRule)."
        ),
    )
    parser.add_argument(
        "--disable-rule",
        dest="disable_rules",
        action="append",
        default=[],
        help=("Disable listed rules (repeatable). Value: rule id or full class name."),
    )
    return parser


def _list_rules() -> int:
    print("Available rules:")
    for rule in default_workflow_rules():
        rule_id = StaticAnalyzer._rule_id(rule)
        rule_fqn = StaticAnalyzer._rule_fqn(rule)
        platforms = sorted(StaticAnalyzer._rule_platforms(rule))
        print(
            f"- ID: {rule_id}\n"
            f"  FQN: {rule_fqn}\n"
            f"  Platforms: {', '.join(platforms)}\n",
        )
    return 0


def _send_notifications(summary: str, findings: list[Finding]) -> None:
    if not findings:
        return
    for channel in channels_from_env():
        channel.send(summary, findings)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.workflow is None and not args.list_rules:
        parser.print_help()
        return 0

    if args.list_rules:
        return _list_rules()

    findings: list[Finding] = []
    if not args.workflow.exists():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="IO Error",
                description=f"File not found: {args.workflow}",
                location=str(args.workflow),
                recommendation="Provide a valid path to workflow.yml.",
            ),
        )
    else:
        secret_engine = SecretDetectionEngine(patterns_path=args.patterns_path)
        enabled = {
            r.strip() for r in args.enable_rules if isinstance(r, str) and r.strip()
        }
        disabled = {
            r.strip() for r in args.disable_rules if isinstance(r, str) and r.strip()
        }

        static_analyzer = StaticAnalyzer(
            secret_engine,
            enabled_rules=enabled if enabled else None,
            disabled_rules=disabled if disabled else None,
            platform=args.platform,
        )
        findings.extend(static_analyzer.analyze_workflow_file(args.workflow))

        if args.log_path is not None:
            if args.log_path.exists():
                log_analyzer = LogAnalyzer(secret_engine)
                findings.extend(
                    log_analyzer.analyze_text(
                        _read_text_file(args.log_path),
                        str(args.log_path),
                    ),
                )
            else:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="IO Warning",
                        description=f"Log file not found: {args.log_path}",
                        location=str(args.log_path),
                        recommendation="Either provide an existing log file or remove --log.",
                    ),
                )

        resolved_platform = static_analyzer.resolved_platform
        summary = (
            f"PipeSec Static Analysis\n"
            f"Found {len(findings)} issues.\n"
            f"Platform: {resolved_platform}\n"
            f"Command line: `{' '.join(sys.argv)}`"
        )
        _send_notifications(summary, findings)

    report = (
        render_json(findings, args.fix)
        if args.format == "json"
        else render_console_report(findings, args.fix)
    )
    if args.out_path:
        args.out_path.write_text(report, encoding="utf-8")
    else:
        print(report)

    threshold_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = threshold_map.get(args.fail_on, 4)
    if _max_severity(findings) >= threshold:
        return 1
    return 0
