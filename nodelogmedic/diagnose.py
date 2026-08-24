from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .redact import redact_line
from .rules import RULES


@dataclass(frozen=True, slots=True)
class DiagnosisConfig:
    """Bounds for deterministic diagnosis.

    ``max_evidence`` is 1..20 and ``max_line_length`` is 256..65536.
    """

    max_evidence: int = 3
    max_line_length: int = 4096

    def __post_init__(self) -> None:
        if not 1 <= self.max_evidence <= 20:
            raise ValueError("max_evidence must be between 1 and 20")
        if not 256 <= self.max_line_length <= 65_536:
            raise ValueError("max_line_length must be between 256 and 65536")


def diagnose_lines(lines: Iterable[str], config: DiagnosisConfig | None = None) -> dict[str, Any]:
    """Redact and diagnose node log lines using deterministic local rules.

    No raw line is included in the returned report. Evidence is bounded per rule.
    """
    active_config = config or DiagnosisConfig()
    matches: dict[str, dict[str, Any]] = {}
    total = 0
    redactions = 0
    for line_number, raw in enumerate(lines, start=1):
        if not isinstance(raw, str):
            raise TypeError("log lines must be text")
        total += 1
        safe, count = redact_line(raw, max_length=active_config.max_line_length)
        redactions += count
        for rule in RULES:
            if not rule.pattern.search(safe):
                continue
            finding = matches.setdefault(rule.rule_id, {
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "title": rule.title,
                "occurrences": 0,
                "explanation": rule.explanation,
                "checks": list(rule.checks),
                "evidence": [],
            })
            finding["occurrences"] += 1
            if len(finding["evidence"]) < active_config.max_evidence:
                finding["evidence"].append({"line": line_number, "text": safe})

    order = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    findings = sorted(matches.values(), key=lambda row: (order[row["severity"]], row["rule_id"]))
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in order}
    return {
        "schema_version": 1,
        "summary": {
            "lines_analyzed": total,
            "redactions": redactions,
            "findings": len(findings),
            "by_severity": counts,
        },
        "findings": findings,
        "limitations": [
            "rules identify matching symptoms, not root-cause proof",
            "unmatched client-specific errors remain unclassified",
            "redaction is defense in depth and cannot guarantee removal of every secret format",
            "the report does not execute repairs or change node configuration",
        ],
    }
