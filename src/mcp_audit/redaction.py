"""Central redaction helpers for reportable audit data."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "<redacted>"
_NAME_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")
_SECRET_NAME = re.compile(
    r"token(?!s(?:$|[_.-]))|api[_-]?key|secret|password|passwd|pwd|credential|"
    r"signature|private[_-]?key|access[_-]?key|session|authorization|authentication|"
    r"(?:^|[_.-])(?:auth|sig)(?:$|[_.-])",
    re.IGNORECASE,
)
_ASSIGNMENT_VALUE = re.compile(r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
_FLAG_VALUE = re.compile(r"(\s+)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC_TOKEN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+")
_URL = re.compile(r"https?://(?:<redacted>|[^\s\"'<>])+", re.IGNORECASE)
_URL_USERINFO = re.compile(r"(https?://)[^/?#\s@]+@", re.IGNORECASE)
_QUERY_VALUE = re.compile(r"=([^&;]*)")
_SECRET_VALUE = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{16,}|xox[abposr]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}"
)
_JWT_HEADER = re.compile(r"eyJ[A-Za-z0-9_-]*")
_JWT_TAIL = re.compile(r"\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

# Field-report identifier scrubbing (opt-in, separate from credential redaction).
_UNIX_HOME = re.compile(r"(/(?:Users|home)/)[^/\s:\"']+")
_WIN_HOME = re.compile(r"([A-Za-z]:\\Users\\)[^\\/\s:\"']+")
_HOST_PLACEHOLDER = "<redacted-host>"


def _is_secret_name(name: str) -> bool:
    # auth/sig must be whole separator-delimited components: author,
    # authority and oauth_callback_port are harmless. Plural tokens are counts,
    # and session-name labels a session rather than authenticating it.
    name = name.lstrip("-")
    return name.lower() != "session-name" and _SECRET_NAME.search(name) is not None


def _redact_named_values(value: str) -> str:
    # Tokenize names first, then match the value at a fixed offset. A pattern
    # like NAME*SECRETNAME* followed by '=' retries quadratically on long names.
    pieces: list[str] = []
    cursor = 0
    for name in _NAME_TOKEN.finditer(value):
        if name.start() < cursor or not _is_secret_name(name.group()):
            continue
        match = _ASSIGNMENT_VALUE.match(value, name.end())
        if match is None and name.group().startswith("-"):
            match = _FLAG_VALUE.match(value, name.end())
        if match is not None:
            # Preserve authentication schemes already scrubbed by the bearer/
            # basic pass, including in Authorization header assignments.
            if match.group(2).lower() in {"bearer", "basic"} and value.startswith(
                " <redacted>", match.end(2)
            ):
                continue
            pieces.extend((value[cursor : match.start(2)], _REDACTED))
            cursor = match.end(2)
    pieces.append(value[cursor:])
    return "".join(pieces)


def _redact_url(match: re.Match[str]) -> str:
    url = _URL_USERINFO.sub(r"\1<redacted>@", match.group())
    url, fragment_marker, _fragment = url.partition("#")
    base, query_marker, query = url.partition("?")
    if query_marker:
        url = base + query_marker + _QUERY_VALUE.sub("=<redacted>", query)
    if fragment_marker:
        url += "#<redacted>"
    return url


def _redact_jwts(value: str) -> str:
    # Consume each candidate header once, even when it contains many 'eyJ'
    # prefixes without a dot. An unanchored three-part JWT regex is quadratic
    # on that input. Tail matching starts only at the end of that header.
    pieces: list[str] = []
    cursor = 0
    for header in _JWT_HEADER.finditer(value):
        if header.start() < cursor or len(header.group()) < 11:
            continue
        tail = _JWT_TAIL.match(value, header.end())
        if tail is not None:
            pieces.extend((value[cursor : header.start()], _REDACTED))
            cursor = tail.end()
    pieces.append(value[cursor:])
    return "".join(pieces)


def redact_text(value: str) -> str:
    """Redact likely credential values while preserving useful context."""
    # URLs first: replacing an assignment must not obscure later query values.
    redacted = _URL.sub(_redact_url, value)
    redacted = _BEARER_TOKEN.sub("Bearer <redacted>", redacted)
    redacted = _BASIC_TOKEN.sub("Basic <redacted>", redacted)
    redacted = _redact_named_values(redacted)
    return _SECRET_VALUE.sub(_REDACTED, _redact_jwts(redacted))


def redact_data(value: Any) -> Any:
    """Recursively redact strings and secret flag/value pairs in JSON-like data."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        result = []
        secret_value = False
        for item in value:
            result.append(_REDACTED if secret_value and isinstance(item, str) else redact_data(item))
            secret_value = (
                isinstance(item, str)
                and item.startswith("-")
                and _NAME_TOKEN.fullmatch(item) is not None
                and _is_secret_name(item)
            )
        return result
    if isinstance(value, dict):
        return {key: redact_data(item) for key, item in value.items()}
    return value


def _compile_alias_pattern(name_aliases: dict[str, str]) -> re.Pattern[str] | None:
    """Build a single word-boundary alternation over the server names to alias.

    Longest names first so a name that is a prefix of another (``git`` vs
    ``github-mcp``) can't shadow the longer match. A single ``re.sub`` pass with
    this pattern means inserted aliases are never re-scanned.
    """
    names = [n for n in name_aliases if n]
    if not names:
        return None
    ordered = sorted(set(names), key=len, reverse=True)
    return re.compile(r"\b(" + "|".join(re.escape(n) for n in ordered) + r")\b")


def _scrub_identifier_text(
    value: str,
    hostname: str | None,
    name_aliases: dict[str, str] | None = None,
    alias_pattern: re.Pattern[str] | None = None,
) -> str:
    """Scrub hostname, home-directory usernames, and server names from one string."""
    if hostname and hostname in value:
        value = value.replace(hostname, _HOST_PLACEHOLDER)
    value = _UNIX_HOME.sub(r"\1<redacted>", value)
    value = _WIN_HOME.sub(r"\1<redacted>", value)
    if alias_pattern is not None and name_aliases is not None:
        aliases = name_aliases
        value = alias_pattern.sub(lambda m: aliases[m.group(0)], value)
    return value


def redact_identifiers(
    value: Any, hostname: str | None = None, name_aliases: dict[str, str] | None = None
) -> Any:
    """Recursively scrub host/username/server-name identifiers from JSON-like data.

    Field-report ("--redact") mode: removes the machine hostname, the username
    segment of home-directory paths (/Users/<name>, /home/<name>,
    C:\\Users\\<name>), and — when ``name_aliases`` is given — replaces each
    server name with a stable alias (``server-01``, …) everywhere it appears:
    structured fields, free-text summaries, and command basenames. So a
    config-only report is safe to share publicly. Credential values are handled
    separately by ``redact_data``; this pass is additive and opt-in. Path
    *shape* is preserved — only the identifying segment is replaced.
    """
    alias_pattern = _compile_alias_pattern(name_aliases) if name_aliases else None
    return _walk_identifiers(value, hostname, name_aliases, alias_pattern)


def _walk_identifiers(
    value: Any,
    hostname: str | None,
    name_aliases: dict[str, str] | None,
    alias_pattern: re.Pattern[str] | None,
) -> Any:
    if isinstance(value, str):
        return _scrub_identifier_text(value, hostname, name_aliases, alias_pattern)
    if isinstance(value, list):
        return [_walk_identifiers(item, hostname, name_aliases, alias_pattern) for item in value]
    if isinstance(value, dict):
        return {
            key: _walk_identifiers(item, hostname, name_aliases, alias_pattern) for key, item in value.items()
        }
    return value
