from __future__ import annotations

import json
from typing import Any

_COLOR = {"critical": "\033[1;31m", "error": "\033[31m", "warning": "\033[33m", "info": "\033[36m"}
_RESET = "\033[0m"


def render_json(report: dict[str, Any]) -> str:
    """Render a stable machine-readable report."""
    return json.dumps(report, indent=2, sort_keys=True)


def render_text(report: dict[str, Any], *, color: bool = False) -> str:
    """Render a compact terminal board from a diagnosis report."""
    summary = report["summary"]
    lines = [
        "NODE LOG MEDIC",
        "=" * 72,
        f"Lines {summary['lines_analyzed']}  Redactions {summary['redactions']}  Findings {summary['findings']}",
        "",
        f"{'SEVERITY':<10} {'COUNT':>5}  FINDING",
        "-" * 72,
    ]
    if not report["findings"]:
        lines.append(f"{'ok':<10} {0:>5}  No known symptom rules matched")
    for finding in report["findings"]:
        severity = finding["severity"]
        label = severity.upper()
        if color:
            label = _COLOR[severity] + label + _RESET
        lines.append(f"{label:<10} {finding['occurrences']:>5}  {finding['title']} [{finding['rule_id']}]")
        for evidence in finding["evidence"]:
            lines.append(f"  L{evidence['line']}: {evidence['text']}")
    lines.extend(("", "Deterministic symptom matches only; inspect limitations in JSON output."))
    return "\n".join(lines)
