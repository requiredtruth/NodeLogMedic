from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .diagnose import DiagnosisConfig, diagnose_lines
from .explain import explain_local
from .render import render_json, render_text


def _read_lines(path: str):
    if path == "-":
        yield from sys.stdin
        return
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        yield from handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redact and diagnose blockchain node logs locally.")
    parser.add_argument("log", help="log file, or - for stdin")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--max-evidence", type=int, default=3, metavar="1..20")
    parser.add_argument("--max-line-length", type=int, default=4096, metavar="256..65536")
    parser.add_argument("--ai-endpoint", help="optional loopback OpenAI-compatible endpoint; requires --format json")
    parser.add_argument("--ai-model", default="local-model")
    args = parser.parse_args(argv)
    try:
        config = DiagnosisConfig(args.max_evidence, args.max_line_length)
        report = diagnose_lines(_read_lines(args.log), config)
        if args.ai_endpoint:
            if args.format != "json":
                raise ValueError("--ai-endpoint requires --format json")
            report["ai_explanation"] = explain_local(report, args.ai_endpoint, args.ai_model)
            report["ai_disclaimer"] = "AI text is commentary; deterministic findings remain authoritative."
    except (OSError, TypeError, ValueError) as exc:
        print(f"nodelogmedic: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(render_json(report))
    else:
        use_color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
        print(render_text(report, color=use_color))
    severe = report["summary"]["by_severity"]
    return 1 if severe["critical"] or severe["error"] or severe["warning"] else 0
