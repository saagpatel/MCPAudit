"""Central redaction helpers for reportable audit data."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
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


@dataclass
class _ExcerptWindow:
    start: int
    end: int

    def replace(self, start: int, end: int, length: int) -> None:
        shift = length - (end - start)
        # Boundaries inside a replacement expand to include the complete token.
        self.start = self.start + shift if self.start >= end else min(self.start, start)
        self.end = self.end + shift if self.end >= end else start + length if self.end > start else self.end


def _apply_edits(
    value: str, edits: Iterable[tuple[int, int, str]], window: _ExcerptWindow | None = None
) -> str:
    pieces: list[str] = []
    cursor = shift = 0
    for start, end, replacement in edits:
        pieces.extend((value[cursor:start], replacement))
        if window is not None:
            window.replace(start + shift, end + shift, len(replacement))
        shift += len(replacement) - (end - start)
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)


def _named_value_edits(value: str, *, protect_urls: bool = False) -> Iterator[tuple[int, int, str]]:
    # Tokenize names first, then match the value at a fixed offset. A pattern
    # like NAME*SECRETNAME* followed by '=' retries quadratically on long names.
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
            # An unquoted URL value belongs to the enclosing assignment/flag,
            # including query delimiters that normally end an unquoted value.
            cursor = url_value.end() if url_value is not None else match.end(2)
            yield match.start(2), cursor, _REDACTED


def _url_edits(value: str) -> Iterator[tuple[int, int, str]]:
    userinfo = _URL_USERINFO.match(value)
    if userinfo is not None:
        yield userinfo.end(1), userinfo.end() - 1, _REDACTED
    base, fragment_marker, _fragment = value.partition("#")
    base, query_marker, query = base.partition("?")
    scheme_end = base.index("://") + 3
    path_start = base.find("/", scheme_end)
    if path_start >= 0:
        offset = path_start + 1
        for segment in base[offset:].split("/"):
            for start, end, replacement in _named_value_edits(segment):
                yield offset + start, offset + end, replacement
            offset += len(segment) + 1
    if query_marker:
        offset = len(base) + 1
        for match in _QUERY_VALUE.finditer(query):
            yield offset + match.start(1), offset + match.end(1), _REDACTED
    if fragment_marker:
        yield value.index("#") + 1, len(value), _REDACTED


def _jwt_edits(value: str) -> Iterator[tuple[int, int, str]]:
    # Consume each candidate header once, even when it contains many 'eyJ'
    # prefixes without a dot. An unanchored three-part JWT regex is quadratic
    # on that input. Tail matching starts only at the end of that header.
    cursor = 0
    for header in _JWT_HEADER.finditer(value):
        if header.start() < cursor or len(header.group()) < 11:
            continue
        tail = _JWT_TAIL.match(value, header.end())
        if tail is not None:
            cursor = tail.end()
            yield header.start(), cursor, _REDACTED


def _redact_text(value: str, window: _ExcerptWindow | None = None) -> str:
    for pattern, replacement in ((_BEARER_TOKEN, "Bearer <redacted>"), (_BASIC_TOKEN, "Basic <redacted>")):
        value = _apply_edits(
            value, ((match.start(), match.end(), replacement) for match in pattern.finditer(value)), window
        )
    # Enclosing assignments see their complete values before URL protection.
    # Names within standalone URLs are handled separately, preserving authority.
    value = _apply_edits(value, _named_value_edits(value, protect_urls=True), window)
    value = _apply_edits(
        value,
        (
            (match.start() + start, match.start() + end, replacement)
            for match in _URL.finditer(value)
            for start, end, replacement in _url_edits(match.group())
        ),
        window,
    )
    value = _apply_edits(value, _jwt_edits(value), window)
    return _apply_edits(
        value, ((match.start(), match.end(), _REDACTED) for match in _SECRET_VALUE.finditer(value)), window
    )


def redact_text(value: str) -> str:
    """Redact likely credential values while preserving useful context."""
    redacted = _redact_text(value)
    return "[metadata excerpt withheld]" if _normalization_exposes_secret(redacted) else redacted


def _normalization_exposes_secret(redacted: str) -> bool:
    from mcp_audit.normalize import normalize_text

    normalized = normalize_text(redacted)
    return _redact_text(normalized) != normalized


def redacted_excerpt(
    text: str,
    start: int,
    end: int,
    *,
    context_before: int = 0,
    context_after: int = 0,
    max_length: int | None = None,
) -> str:
    """Redact the whole field, map its raw match span, then slice and render.

    A match overlapping a credential includes its complete replacement token.
    Context counts refer to the redacted text, so discarded credential labels
    cannot leave an unrecognized tail in evidence.
    """
    from mcp_audit.normalize import render_invisibles

    if context_before < 0 or context_after < 0 or (max_length is not None and max_length < 0):
        raise ValueError("Invalid excerpt span or context")
    start = min(len(text), max(0, start))
    end = min(len(text), max(start, end))
    window = _ExcerptWindow(start, end)
    redacted = _redact_text(text, window)
    # A label can become recognizable only after Unicode normalization. If
    # raw-field redaction missed such a value, withhold the field's evidence
    # altogether rather than copy any raw or normalized part of that value.
    if _normalization_exposes_secret(redacted):
        withheld = "[metadata excerpt withheld]"
        return withheld if max_length is None else withheld[:max_length]
    before = render_invisibles(redacted[max(0, window.start - context_before) : window.start])
    match = render_invisibles(redacted[window.start : window.end])
    after = render_invisibles(redacted[window.end : window.end + context_after])
    if max_length is not None:
        # Expanded invisible markers must not push the actual match out of view.
        if len(before) + len(match) > max_length:
            before = ""
        return (before + match + after)[:max_length]
    return before + match + after


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
