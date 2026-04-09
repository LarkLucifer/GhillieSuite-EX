"""
ghilliesuite_ex/utils/redaction.py
──────────────────────────────────
Centralized redaction helpers for evidence and report output.

These helpers are intentionally conservative: they preserve enough context for
triage while masking credentials, bearer tokens, cookies, and common API
secret formats before anything is written to disk.
"""

from __future__ import annotations

import re
from typing import Pattern

_REDACTED = "[REDACTED]"
_REDACTED_SECRET = "[REDACTED_SECRET]"

_HEADER_NAMES = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "api-key",
    "apikey",
)

_HEADER_LINE_RE = re.compile(
    rf"(?im)^((?:{'|'.join(re.escape(name) for name in _HEADER_NAMES)}))\s*:\s*(.+)$"
)
_INLINE_HEADER_RE = re.compile(
    rf"(?i)\b((?:{'|'.join(re.escape(name) for name in _HEADER_NAMES)}))\s*:\s*([^\r\n]+)"
)

_KEY_VALUE_PATTERNS: list[Pattern[str]] = [
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password)\b"
        r"(\s*[:=]\s*[\"']?)([A-Za-z0-9_\-./+=]{8,})([\"']?)"
    ),
    re.compile(
        r"(?i)([?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|token|key|secret|password)=)"
        r"([^&#\\s]+)"
    ),
]

_SECRET_PATTERNS: list[Pattern[str]] = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.IGNORECASE),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]


def _redact_header_line(match: re.Match[str]) -> str:
    return f"{match.group(1)}: {_REDACTED}"


def _redact_assignment(match: re.Match[str]) -> str:
    if len(match.groups()) == 4:
        key, separator, _, quote = match.groups()
        return f"{key}{separator}{_REDACTED_SECRET}{quote}"
    prefix, _ = match.groups()
    return f"{prefix}{_REDACTED_SECRET}"


def redact_text(value: str | bytes | None) -> str:
    """
    Redact sensitive values from free-form text before writing to disk.

    Redacts:
    - Cookie/Authorization and similar auth headers
    - Bearer tokens
    - Common API key / token / secret assignments
    - Common credential formats (JWT, OpenAI, GitHub, Slack, Stripe, etc.)
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    text = _HEADER_LINE_RE.sub(_redact_header_line, text)
    text = _INLINE_HEADER_RE.sub(_redact_header_line, text)

    for pattern in _KEY_VALUE_PATTERNS:
        text = pattern.sub(_redact_assignment, text)

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_REDACTED_SECRET, text)

    return text
