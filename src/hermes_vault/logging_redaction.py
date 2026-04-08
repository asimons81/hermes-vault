from __future__ import annotations

import logging
import re
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*([^\s,'\"]+)"),
    re.compile(r"\b(sk-[A-Za-z0-9]{12,})\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{12,})\b"),
    re.compile(r"\bya29\.[A-Za-z0-9._-]+\b"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_replace_match, redacted)
    return redacted


def _replace_match(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex > 1:
        groups = list(match.groups())
        groups[-1] = "[REDACTED]"
        return "=".join(groups[:2]) if len(groups) == 2 else "[REDACTED]"
    return "[REDACTED]"


def redact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if any(token in key.lower() for token in ("key", "token", "secret", "password")):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = redact_mapping(value)
        elif isinstance(value, str):
            redacted[key] = redact_text(value)
        else:
            redacted[key] = value
    return redacted


def safe_exception_message(exc: BaseException) -> str:
    return redact_text(str(exc))


def redact_exception(exc: BaseException) -> str:
    return safe_exception_message(exc)


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return redact_text(rendered)
