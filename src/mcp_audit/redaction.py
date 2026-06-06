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

# Field-report identifier scrubbing (opt-in, separate from credential redaction).
_UNIX_HOME = re.compile(r"(/(?:Users|home)/)[^/\s:\"']+")
_WIN_HOME = re.compile(r"([A-Za-z]:\\Users\\)[^\\/\s:\"']+")
_HOST_PLACEHOLDER = "<redacted-host>"


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


def _scrub_identifier_text(value: str, hostname: str | None) -> str:
    """Scrub the machine hostname and home-directory usernames from one string."""
    if hostname and hostname in value:
        value = value.replace(hostname, _HOST_PLACEHOLDER)
    value = _UNIX_HOME.sub(r"\1<redacted>", value)
    return _WIN_HOME.sub(r"\1<redacted>", value)


def redact_identifiers(value: Any, hostname: str | None = None) -> Any:
    """Recursively scrub host/username identifiers from JSON-like data.

    Field-report ("--redact") mode: removes the machine hostname and the
    username segment of home-directory paths (/Users/<name>, /home/<name>,
    C:\\Users\\<name>) so a config-only report is safe to share publicly.
    Credential values are handled separately by ``redact_data``; this pass is
    additive and opt-in. Path *shape* is preserved — only the identifying
    segment is replaced.
    """
    if isinstance(value, str):
        return _scrub_identifier_text(value, hostname)
    if isinstance(value, list):
        return [redact_identifiers(item, hostname) for item in value]
    if isinstance(value, dict):
        return {key: redact_identifiers(item, hostname) for key, item in value.items()}
    return value
