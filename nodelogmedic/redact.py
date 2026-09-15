from __future__ import annotations

import re

_QUOTED_VALUE = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
_AUTHORIZATION = re.compile(
    rf"(?i)(?<![\w-])[\"']?authorization[\"']?\s*[:=]\s*"
    rf"(?:{_QUOTED_VALUE}|(?:basic|bearer)\s+[^\s,;}}\]]+|[^\s,;}}\]]+)"
)
_CREDENTIAL = re.compile(
    rf"(?i)(?<![\w-])[\"']?(?:api[_-]?key|client[_-]?secret|password|private[_-]?key|"
    rf"refresh[_-]?token|access[_-]?token|secret|token|jwt)[\"']?\s*[:=]\s*"
    rf"(?:{_QUOTED_VALUE}|[^\s,;}}\]]+)"
)

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (_AUTHORIZATION, "[SECRET]"),
    (_CREDENTIAL, "[SECRET]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[JWT]"),
    (re.compile(r"(?i)\b(?:https?|wss?)://[^\s]+"), "[URL]"),
    (re.compile(r"(?i)0x[0-9a-f]{64}\b"), "[HEX_32_BYTES]"),
    (re.compile(r"(?i)0x[0-9a-f]{40}\b"), "[EVM_ADDRESS]"),
    (re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?\b"), "[IP_ADDRESS]"),
    (re.compile(r"(?<![\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%[\w.-]+)?"), "[IP_ADDRESS]"),
    (re.compile(r"(?<![\w.-])(?:/[\w.@+,:=-]+){2,}(?:/[\w.@+,:=-]*)?"), "[PATH]"),
    (re.compile(r"(?i)\b[A-Z]:\\(?:[^\s\\]+\\)+[^\s]*"), "[PATH]"),
)


def redact_line(line: str, *, max_length: int = 4096) -> tuple[str, int]:
    """Return a bounded redacted log line and the number of substitutions.

    The original string is never retained by this function. ``max_length`` must
    be between 256 and 65536 characters.
    """
    if not isinstance(line, str):
        raise TypeError("line must be text")
    if not 256 <= max_length <= 65_536:
        raise ValueError("max_length must be between 256 and 65536")
    value = line.rstrip("\r\n")
    substitutions = 0
    for pattern, replacement in _RULES:
        value, count = pattern.subn(replacement, value)
        substitutions += count
    return value[:max_length], substitutions
