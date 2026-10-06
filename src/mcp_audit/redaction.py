"""Central redaction helpers for reportable audit data."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "<redacted>"
_NAME_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")
_SESSION_LABEL = re.compile(r"(?<![A-Za-z0-9])session[_-]name(?=$|[_.-])", re.IGNORECASE)
_SECRET_NAME = re.compile(
    r"token(?!s(?:$|[_.-])|izer(?:$|[_.-]))|api[_-]?key|secret|password|passwd|pwd|credential|"
    r"signature|private[_-]?key|access[_-]?key|session|authorization|authentication|"
    r"(?:^|[_.-])(?:auth|sig)(?:$|[_.-])",
    re.IGNORECASE,
)
_ASSIGNMENT_PREFIX = re.compile(r"[\"']?\s*[:=]\s*")
_ASSIGNMENT_VALUE = re.compile(
    r"([\"']?\s*[:=]\s*)(<redacted>(?=$|[\s,;&\"'}\]])|"
    r"\"(?:\\.|[^\"\\])*+\"|'(?:\\.|[^'\\])*+'|[^\s,;&\"']+)"
)
_FLAG_VALUE = re.compile(r"(\s+)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC_TOKEN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+")
# Consume scheme-like runs once; a nested scheme ends the current path span.
# Query values and fragments still consume their entire enclosing URL tail.
_URL = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*+://"
    r"(?:<redacted>|[A-Za-z][A-Za-z0-9+.-]*+(?!://)|"
    r"[0-9+.-][A-Za-z0-9+.-]*+|[?#](?:<redacted>|[^\s\"'<>])*+|"
    r"[^\s\"'<>A-Za-z0-9+.?#-])++"
)
# Whole secret values include nested URLs; standalone spans stop at each scheme.
_URL_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*+://(?:<redacted>|[^\s\"'<>])++")
_URL_USERINFO = re.compile(r"(^[A-Za-z][A-Za-z0-9+.-]*+://)(?:[^/?#\s@]*+@)++")
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
    # tokenizer selects a tokenizer; session_name/session-name components label
    # a session rather than authenticate it. session_id remains secret-bearing.
    name = name.lstrip("-")
    name = _SESSION_LABEL.sub("label", name)
    return _SECRET_NAME.search(name) is not None


def _redact_named_values(value: str, *, protect_urls: bool = False) -> str:
    # Tokenize names first, then match the value at a fixed offset. A pattern
    # like NAME*SECRETNAME* followed by '=' retries quadratically on long names.
    pieces: list[str] = []
    cursor = 0
    urls = _URL.finditer(value) if protect_urls else iter(())
    url = next(urls, None)
    for name in _NAME_TOKEN.finditer(value):
        while url is not None and name.start() >= url.end():
            url = next(urls, None)
        if name.start() < cursor or not _is_secret_name(name.group()):
            continue
        if url is not None and name.start() >= url.start():
            prefix = _ASSIGNMENT_PREFIX.match(value, name.end())
            if prefix is None or _URL_VALUE.match(value, prefix.end()) is None:
                continue
        match = _ASSIGNMENT_VALUE.match(value, name.end())
        if match is None and name.group().startswith("-"):
            match = _FLAG_VALUE.match(value, name.end())
        if match is not None:
            url_value = _URL_VALUE.match(value, match.start(2))
            # Preserve authentication schemes already scrubbed by the bearer/
            # basic pass, including in Authorization header assignments.
            if match.group(2).lower() in {"bearer", "basic"} and value.startswith(
                " <redacted>", match.end(2)
            ):
                continue
            pieces.extend((value[cursor : match.start(2)], _REDACTED))
            # An unquoted URL value belongs to the enclosing assignment/flag,
            # including query delimiters that normally end an unquoted value.
            cursor = url_value.end() if url_value is not None else match.end(2)
    pieces.append(value[cursor:])
    return "".join(pieces)


def _redact_url(match: re.Match[str]) -> str:
    url = _URL_USERINFO.sub(r"\1<redacted>@", match.group())
    url, fragment_marker, _fragment = url.partition("#")
    base, query_marker, query = url.partition("?")
    scheme, _, remainder = base.partition("://")
    authority, path_marker, path = remainder.partition("/")
    url = scheme + "://" + authority
    if path_marker:
        url += "/" + "/".join(_redact_named_values(segment) for segment in path.split("/"))
    if query_marker:
        url += query_marker + _QUERY_VALUE.sub("=<redacted>", query)
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
    redacted = _BEARER_TOKEN.sub("Bearer <redacted>", value)
    redacted = _BASIC_TOKEN.sub("Basic <redacted>", redacted)
    # Enclosing assignments see their complete values before URL protection.
    # Names within standalone URLs are handled separately, preserving authority.
    redacted = _redact_named_values(redacted, protect_urls=True)
    redacted = _URL.sub(_redact_url, redacted)
    return _SECRET_VALUE.sub(_REDACTED, _redact_jwts(redacted))


def _redact_literal_strings(value: object) -> object:
    """Hide string literals in secret-property defaults/examples/const, retaining shape."""
    if isinstance(value, str):
        return _REDACTED
    if isinstance(value, list):
        return [_redact_literal_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_literal_strings(item) for key, item in value.items()}
    return value


def _redact_properties(properties: dict[object, object]) -> dict[object, object]:
    result: dict[object, object] = {}
    for name, schema in properties.items():
        if isinstance(name, str) and _is_secret_name(name) and isinstance(schema, dict):
            result[name] = {
                key: _redact_literal_strings(item)
                if key in {"default", "examples", "const"}
                else redact_data(item)
                for key, item in schema.items()
            }
        else:
            result[name] = redact_data(schema)
    return result


def redact_data(value: Any) -> Any:
    """Recursively redact strings and secret flag/value pairs in JSON-like data."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        result = []
        secret_value = False
        for item in value:
            if isinstance(item, str):
                name = _NAME_TOKEN.match(item)
                if secret_value and not item.startswith("-"):
                    result.append(_REDACTED)
                elif (
                    name is not None
                    and _is_secret_name(name.group())
                    and item[name.end() :].startswith(("=", ":"))
                    and _URL.match(item) is None
                ):
                    # One argv element has a known boundary, even when its value
                    # contains spaces, commas, ampersands or embedded quotes.
                    result.append(item[: name.end() + 1] + _REDACTED)
                else:
                    result.append(redact_text(item))
            else:
                result.append(redact_data(item))
            secret_value = (
                isinstance(item, str)
                and item.startswith("-")
                and _NAME_TOKEN.fullmatch(item) is not None
                and _is_secret_name(item)
            )
        return result
    if isinstance(value, dict):
        return {
            key: _REDACTED
            if isinstance(key, str) and _is_secret_name(key) and isinstance(item, str)
            else _redact_properties(item)
            if key == "properties" and isinstance(item, dict)
            else redact_data(item)
            for key, item in value.items()
        }
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
