"""Central redaction helpers for reportable audit data."""

from __future__ import annotations

import re
from typing import Any

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(token|api[_-]?key|apikey|secret|password|credential)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC_TOKEN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+")
_URL_USERINFO = re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@")


def redact_text(value: str) -> str:
    """Redact likely credential values while preserving useful context."""
    redacted = _BEARER_TOKEN.sub("Bearer <redacted>", value)
    redacted = _BASIC_TOKEN.sub("Basic <redacted>", redacted)
    redacted = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", redacted)
    return _URL_USERINFO.sub(r"\1<redacted>@", redacted)


def redact_data(value: Any) -> Any:
    """Recursively redact strings in JSON-like data."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_data(item) for key, item in value.items()}
    return value
