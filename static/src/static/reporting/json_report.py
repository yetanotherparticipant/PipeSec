from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from static.models import Finding


def to_json_dict(findings: list[Finding], show_fix: bool = False) -> dict[str, Any]:
    items = []
    for f in findings:
        d = asdict(f)
        if not show_fix and "fix" in d:
            d.pop("fix")
        items.append(d)

    return {
        "findings": items,
        "count": len(findings),
        "countsBySeverity": {
            sev: sum(1 for f in findings if f.severity.value == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
    }


def render_json(findings: list[Finding], show_fix: bool = False) -> str:
    return json.dumps(to_json_dict(findings, show_fix), indent=2, ensure_ascii=False)
