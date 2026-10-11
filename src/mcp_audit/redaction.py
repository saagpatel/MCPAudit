"""Central redaction helpers for reportable audit data."""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from collections.abc import Callable, Iterable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from itertools import accumulate, product
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel

from mcp_audit.normalize import normalize_text
from mcp_audit.terminal_text import control_free_spans, strip_controls

_REDACTED = "<redacted>"
_MAX_PASSES = 4
_REPORT_REDACTOR: ContextVar[Callable[[str], str] | None] = ContextVar("report_redactor", default=None)
_NAME_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")
_SESSION_LABEL = re.compile(r"(?<![A-Za-z0-9])session[_-]name(?=$|[_.-])", re.IGNORECASE)
_SECRET_NAME = re.compile(
    r"token(?!s(?:$|[_.-])|izer(?:$|[_.-]))|api[_-]?key|secret|password|passwd|pwd|credential|"
    r"signature|private[_-]?key|access[_-]?key|session|authorization|authentication|"
    r"(?:^|[_.-])(?:auth|sig)(?:$|[_.-])",
    re.IGNORECASE,
)
# Every (overlapping) secret-label match, so a literal byte is never hidden by a neighbour.
_SECRET_LABELS = re.compile(f"(?=({_SECRET_NAME.pattern}))", re.IGNORECASE)
# Escape framing and controls; what is left of a removed run is its printable bytes.
_RUN_FRAMING = re.compile(r"\x1b[\[\]\\]?|[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# Readings of one whitespace-free chunk before it is ambiguous.
_MAX_READINGS = 1024
# Reading characters a field may enumerate: a floor plus a share per character,
# so the work for every reading consumer of one field stays linear.
_WORK_FLOOR = 1 << 18
_LABEL_WORK_FLOOR = 1 << 12
_WORK_PER_CHAR = 16
# Delimiter-only or escape-only tokens a window joins between a label and its value.
_MAX_JOINED = 8
# Suffix readings enumerated per escape sequence. A longer sequence is not
# enumerated: every window holding it is ambiguous and withheld, which is
# never less conservative than enumerating it, and keeps the cost linear.
_MAX_SUFFIX = 64
# A value is a run of quoted and unquoted segments, as in a shell word, so a
# replacement never stops where a second pass would continue. A backslash
# escapes the next character; an unterminated quoted segment runs to the end
# of the field; ': ' ends a value, as does a closing bracket right after a
# closing quote, matching the redacted-token lookahead.
_REDACTED_VALUE = r"<redacted>(?=$|[\s,;&\"'}\]]|:(?:\s|$|<redacted>)|⟧(?=$|[\s,;&\"'}\]]))"
_VALUE = (
    r"(?:\"(?:\\[\s\S]|[^\"\\])*+(?:\"|\\?\Z)|'(?:\\[\s\S]|[^'\\])*+(?:'|\\?\Z)|"
    r"\\[\s\S]|(?!:(?:\s|\Z))(?!(?<=[^\\][\"'])[}\]])[^\s,;&\"'])++"
)
_VALUE_CONTINUATION = re.compile(_VALUE)
_ASSIGNMENT_PREFIX = re.compile(r"[\"']?\s*[:=]\s*")
_ASSIGNMENT_VALUE = re.compile(rf"([\"']?\s*[:=]\s*)({_REDACTED_VALUE}|{_VALUE})")
_FLAG_VALUE = re.compile(rf"(\s+)({_REDACTED_VALUE}|{_VALUE})")
_FLAG_PREFIX = re.compile(r"\s*")
# Credentials share the value grammar: angle brackets and quotes never split one.
_BEARER_TOKEN = re.compile(rf"(?i)\bBearer\s+(<redacted>|{_VALUE})")
_BASIC_TOKEN = re.compile(rf"(?i)\bBasic\s+(<redacted>|{_VALUE})")
# Consume scheme-like runs once; a nested scheme ends the current path span.
# Query values and fragments still consume their entire enclosing URL tail.
_URL = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*+://"
    r"(?:<redacted>|\\[\"']|[A-Za-z][A-Za-z0-9+.-]*+(?!://)|"
    r"[0-9+.-][A-Za-z0-9+.-]*+|[?#](?:<redacted>|\\[\"']|[^\s\"'<>])*+|"
    r"[^\s\"'<>A-Za-z0-9+.?#-])++"
)
# Whole secret values include nested URLs; standalone spans stop at each scheme.
_URL_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*+://(?:<redacted>|\\[\"']|[^\s\"'<>])++")
_URL_USERINFO = re.compile(r"(^[A-Za-z][A-Za-z0-9+.-]*+://)(?:[^/?#\s@]*+@)++")
_TOKEN_TAIL = re.compile(r"\S*")
_SPACED_AT = re.compile(r"\s@")
_SPACED_USERINFO = re.compile(r"[^\S\r\n]+@")
_AUTHORITY_END = re.compile(r"[/?#]")
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


class _Budget:
    """Reading characters one field may still enumerate, shared by every consumer.

    It also remembers label answers for the field; nothing outlives the field.
    """

    __slots__ = ("labels", "left")

    def __init__(self, size: int, floor: int = _WORK_FLOOR) -> None:
        self.left = floor + _WORK_PER_CHAR * size
        self.labels: dict[str, bool] = {}

    def charge(self, cost: int) -> bool:
        """Spend ``cost``; False once the field's work is spent (the caller withholds)."""
        self.left -= cost
        return self.left >= 0


def _is_secret_name(name: str, budget: _Budget | None = None) -> bool:
    """A raw label is secret in its detection reading or in any literal reading.

    Every consumer (free-text labels, argv flags, schema property names and
    JSON keys) asks this one question of the raw label, so a label split by an
    escape sequence gets the same answer everywhere. Enumerating its readings
    is charged to ``budget`` (the enclosing field's, or the label's own); a
    label whose readings the budget cannot cover is treated as secret.
    """
    if budget is not None and (known := budget.labels.get(name)) is not None:
        return known
    plain = strip_controls(name)
    if _plain_secret_name(plain):
        return True
    if plain == name:
        return False
    result = _literal_secret_name(name, budget or _Budget(len(name), _LABEL_WORK_FLOOR))
    if result is None:
        return True  # Budget spent: conservative, and not remembered.
    if budget is not None:
        budget.labels[name] = result
    return result


def _plain_secret_name(name: str) -> bool:
    # auth/sig must be whole separator-delimited components: author,
    # authority and oauth_callback_port are harmless. Plural tokens are counts,
    # tokenizer selects a tokenizer; session_name/session-name components label
    # a session rather than authenticate it. session_id remains secret-bearing.
    name = (name if name.isascii() else normalize_text(name)).lstrip("-")
    name = _SESSION_LABEL.sub("label", name)
    return _SECRET_NAME.search(name) is not None


# One reading choice for a segment: its text, each character's raw index, and
# whether the text comes from a removed run.
_Choice = tuple[str, tuple[int, ...], bool]


@dataclass(frozen=True)
class _Segment:
    start: int
    end: int
    choices: tuple[_Choice, ...]
    # False when the choices omit readings (a sequence longer than _MAX_SUFFIX).
    complete: bool = True


@dataclass(frozen=True)
class _Reading:
    """One reading of raw text: its characters, their raw indexes, and which came from removed runs."""

    text: str
    origins: tuple[int, ...]
    literal: tuple[bool, ...]


def _printable_spans(value: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    """Printable ranges of a removed run once escape framing and controls go."""
    for framing in _RUN_FRAMING.finditer(value, start, end):
        if start < framing.start():
            yield start, framing.start()
        start = framing.end()
    if start < end:
        yield start, end


def _segments(value: str) -> list[_Segment]:
    """Retained text and removed runs, each with the ways it can be read.

    Detection drops a removed run, but a terminal or a reader of the raw field
    may take its printable bytes literally: a CSI/C1 final byte (``ESC [ s``),
    its parameters and intermediates, an OSC payload or the byte after a bare
    ESC. A sequence may have been meant to end earlier than the parser ended
    it (a CSI consumes parameter and intermediate bytes greedily; an OSC runs
    to its terminator), so each sequence in a removed run reads as dropped or
    as any suffix of its printable bytes. The longest reading is always last.
    Only suffixes up to ``_MAX_SUFFIX`` characters are built (plus the whole
    payload), so building segments is linear; a longer sequence's segment is
    marked incomplete and makes every window that holds it ambiguous.
    """
    segments: list[_Segment] = []
    cursor = 0
    for start, end in (*control_free_spans(value), (len(value), len(value))):
        # Adjacent sequences form one removed run; each one is read on its own.
        cuts = [
            index
            for index in range(cursor + 1, start)
            if value[index] in "\x1b\x9b\x9d" and not value.startswith("\x1b\\", index)
        ]
        for left, right in zip([cursor, *cuts], [*cuts, start], strict=True):
            if left < right:
                choices, complete = _sequence_choices(value, left, right)
                segments.append(_Segment(left, right, choices, complete))
        if start < end:
            segments.append(_Segment(start, end, ((value[start:end], tuple(range(start, end)), False),)))
        cursor = end
    return segments


def _sequence_choices(value: str, start: int, end: int) -> tuple[tuple[_Choice, ...], bool]:
    """Dropped, each suffix up to ``_MAX_SUFFIX``, then the whole payload; and whether that is all."""
    printable = tuple(
        index for left, right in _printable_spans(value, start, end) for index in range(left, right)
    )
    choices: dict[str, _Choice] = {"": ("", (), True)}
    for length in (*range(1, min(len(printable), _MAX_SUFFIX) + 1), len(printable)):
        indexes = printable[len(printable) - length :]
        text = "".join(value[index] for index in indexes)
        choices.setdefault(text, (text, indexes, True))
    return tuple(choices.values()), len(printable) <= _MAX_SUFFIX


def _chunks(segments: list[_Segment]) -> Iterator[list[_Segment]]:
    """Whitespace-free chunks: retained whitespace splits, removed whitespace does not."""
    chunk: list[_Segment] = []
    for segment in segments:
        text, indexes, literal = segment.choices[0]
        if literal:
            chunk.append(segment)
            continue
        cursor = 0
        for space in re.finditer(r"\s+", text):
            if cursor < space.start():
                piece = (text[cursor : space.start()], indexes[cursor : space.start()], False)
                chunk.append(_Segment(indexes[cursor], indexes[space.start() - 1] + 1, (piece,)))
            yield chunk
            chunk = []
            cursor = space.end()
        if cursor < len(text):
            chunk.append(_Segment(indexes[cursor], segment.end, ((text[cursor:], indexes[cursor:], False),)))
    yield chunk


def _reading_count(chunk: list[_Segment]) -> int:
    """Number of readings, stopping once past the limit (no huge products).

    A segment with unenumerated readings counts as past the limit.
    """
    count = 1
    for segment in chunk:
        if not segment.complete:
            return _MAX_READINGS + 1
        count *= len(segment.choices)
        if count > _MAX_READINGS:
            break
    return count


def _readings(chunk: list[_Segment]) -> Iterator[_Reading] | None:
    """Every combination of run choices, or None when too many runs make it ambiguous."""
    if _reading_count(chunk) > _MAX_READINGS:
        return None
    return (
        _Reading(
            "".join(text for text, _, _ in combination),
            tuple(index for _, indexes, _ in combination for index in indexes),
            tuple(literal for text, _, literal in combination for _ in text),
        )
        for combination in product(*(segment.choices for segment in chunk))
    )


def _literal_secret_name(name: str, budget: _Budget) -> bool | None:
    """Reading removed printable bytes literally completes a secret label.

    Every combination of run readings is tried. A reading counts only when a
    secret-label match covers a literal byte: a byte that merely ends an
    exclusion (the ``m`` of a colour reset after ``tokens``) is not a label.
    A chunk with too many such runs to enumerate is ambiguous and counts.
    Each chunk's readings are charged to ``budget`` before they are built;
    None when it is spent.
    """
    for chunk in _chunks(_segments(name)):
        if not any(len(segment.choices) > 1 for segment in chunk):
            continue
        count = _reading_count(chunk)
        if count > _MAX_READINGS:
            return True
        if not budget.charge(count * (chunk[-1].end - chunk[0].start)):
            return None
        readings = _readings(chunk)
        if readings is None:
            return True
        if any(
            any(reading.literal) and _covers_literal(reading.text, list(reading.literal))
            for reading in readings
        ):
            return True
    return False


def _covers_literal(text: str, literal: list[bool]) -> bool:
    if not text.isascii():
        pieces = [normalize_text(char) for char in text]
        if "".join(pieces) != normalize_text(text):
            # No per-character map: judge the whole reading.
            return _plain_secret_name(text)
        literal = [flag for piece, flag in zip(pieces, literal, strict=True) for _ in piece]
        text = "".join(pieces)
    stripped = len(text) - len(text.lstrip("-"))
    text, literal = text[stripped:], literal[stripped:]
    parts: list[str] = []
    marks: list[bool] = []
    cursor = 0
    for label in _SESSION_LABEL.finditer(text):
        parts.extend((text[cursor : label.start()], "label"))
        marks.extend([*literal[cursor : label.start()], *[False] * len("label")])
        cursor = label.end()
    parts.append(text[cursor:])
    marks.extend(literal[cursor:])
    counts = list(accumulate(marks, initial=0))
    return any(
        counts[match.end(1)] > counts[match.start(1)] for match in _SECRET_LABELS.finditer("".join(parts))
    )


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


def _named_value_edits(
    value: str,
    *,
    protect_urls: bool = False,
    empty_values: bool = False,
    labels: frozenset[int] | None = None,
    base: int = 0,
) -> Iterator[tuple[int, int, str]]:
    # ``labels``, when given, holds the secret label starts of the enclosing
    # detection text, where ``value`` starts at ``base``.
    # Tokenize names first, then match the value at a fixed offset. A pattern
    # like NAME*SECRETNAME* followed by '=' retries quadratically on long names.
    cursor = 0
    urls = _URL.finditer(value) if protect_urls else iter(())
    url = next(urls, None)
    for name in _NAME_TOKEN.finditer(value):
        while url is not None and name.start() >= url.end():
            url = next(urls, None)
        if name.start() < cursor or not (
            base + name.start() in labels if labels is not None else _is_secret_name(name.group())
        ):
            continue
        if url is not None and name.start() >= url.start():
            prefix = _ASSIGNMENT_PREFIX.match(value, name.end())
            if prefix is None or _URL_VALUE.match(value, prefix.end()) is None:
                continue
        match = _ASSIGNMENT_VALUE.match(value, name.end())
        if match is None and name.group().startswith("-"):
            match = _FLAG_VALUE.match(value, name.end())
        if match is None and empty_values:
            # In detection text a value can be empty because its raw bytes were
            # removed (an escape sequence) or normalization created a terminator.
            # Mark the empty value; the caller maps it to raw bytes or withholds.
            prefix = _ASSIGNMENT_PREFIX.match(value, name.end())
            if prefix is None and name.group().startswith("-"):
                prefix = _FLAG_PREFIX.match(value, name.end())
            if prefix is not None:
                yield prefix.end(), prefix.end(), _REDACTED
            continue
        if match is not None:
            url_value = _URL_VALUE.match(value, match.start(2))
            # The bearer/basic detector owns the credential span, retaining
            # the raw authentication scheme in Authorization assignments.
            if match.group(2).lower() in {"bearer", "basic"} and any(
                pattern.match(value, match.start(2)) for pattern in (_BEARER_TOKEN, _BASIC_TOKEN)
            ):
                continue
            # An unquoted URL value belongs to the enclosing assignment/flag,
            # including query delimiters that normally end an unquoted value.
            cursor = max(url_value.end(), match.end(2)) if url_value is not None else match.end(2)
            yield match.start(2), cursor, _REDACTED


def _ambiguous_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return True
    # A compatibility-spelled scheme is not recognized by the raw parser.
    scheme = value.partition("://")[0] if "://" in value else parts.scheme
    return not parts.scheme or any(
        unicodedata.normalize("NFKC", part) != part for part in (scheme, parts.netloc)
    )


def _url_edits(
    value: str, *, raw: bool = True, labels: frozenset[int] | None = None, at: int = 0
) -> Iterator[tuple[int, int, str]]:
    """URL credential spans; path labels use ``labels`` with ``value`` at ``at`` in their text."""
    if raw and _ambiguous_url(value):
        # Free-text copies need the same protection as complete URL fields.
        yield 0, len(value), _REDACTED
        return
    userinfo = _URL_USERINFO.match(value)
    base, fragment_marker, _fragment = value.partition("#")
    base, query_marker, query = base.partition("?")
    scheme_end = base.index("://") + 3
    if userinfo is not None:
        yield userinfo.end(1), userinfo.end() - 1, _REDACTED
    else:
        # 'X:Y' in a netloc is userinfo unless Y is a port: in free text a
        # password can be cut from its '@' (a space before it, say).
        authority_end = base.find("/", scheme_end) % (len(base) + 1)
        authority = base[scheme_end:authority_end]
        if _netloc_password(authority):
            colon = authority.find(":", authority.find("]") + 1 if authority.startswith("[") else 0)
            yield scheme_end + colon + 1, authority_end, _REDACTED
    path_start = base.find("/", scheme_end)
    if path_start >= 0:
        offset = path_start + 1
        for segment in base[offset:].split("/"):
            for start, end, replacement in _named_value_edits(segment, labels=labels, base=at + offset):
                yield offset + start, offset + end, replacement
            offset += len(segment) + 1
    if query_marker:
        offset = len(base) + 1
        for match in _QUERY_VALUE.finditer(query):
            yield offset + match.start(1), offset + match.end(1), _REDACTED
    if fragment_marker:
        yield value.index("#") + 1, len(value), _REDACTED


def _token_end(value: str, start: int) -> int:
    match = _TOKEN_TAIL.match(value, start)
    return start if match is None else match.end()


class _NextFinder:
    """First position at or after ``start`` of a substring or pattern, cached.

    Callers ask with non-decreasing starts, so each search runs once per hit.
    """

    def __init__(self, value: str) -> None:
        self.value = value
        self.found: dict[str | re.Pattern[str], int] = {}

    def __call__(self, key: str | re.Pattern[str], start: int) -> int:
        found = self.found.get(key, -1)
        if found < start:
            if isinstance(key, str):
                found = self.value.find(key, start)
            else:
                match = key.search(self.value, start)
                found = -1 if match is None else match.start()
            found = len(self.value) if found < 0 else found
            self.found[key] = found
        return found


def _netloc_password(authority: str) -> bool:
    """``X:Y`` where ``Y`` is not a numeric port: ``Y`` is a userinfo password."""
    colon = authority.find(":", authority.find("]") + 1 if authority.startswith("[") else 0)
    port = authority[colon + 1 :]
    return colon >= 0 and bool(port) and not port.isdigit()


def _truncated_url(url: str, userinfo_follows: bool) -> bool:
    """The component a quote or angle bracket cut short can carry a credential.

    That is a query or fragment, an authority that userinfo continues or that
    already holds a password, or a final path segment whose named value runs
    to the cut.
    """
    rest = url[url.index("://") + 3 :]
    if "?" in rest or "#" in rest:
        return True
    if "/" not in rest:
        return userinfo_follows or _netloc_password(rest)
    segment = rest.rpartition("/")[2]
    return _ends_with_secret_label(segment) or any(
        end == len(segment) for _, end, _ in _named_value_edits(segment)
    )


def _ends_with_secret_label(text: str) -> bool:
    """``NAME=`` or ``NAME:`` at the end of ``text``, scanned backward in linear time."""
    head = text.rstrip()
    if head[-1:] not in {"=", ":"}:
        return False
    head = head[:-1].rstrip().rstrip("\"'")
    start = len(head)
    while start and (head[start - 1].isascii() and (head[start - 1].isalnum() or head[start - 1] in "_.-")):
        start -= 1
    return start < len(head) and _is_secret_name(head[start:])


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


def _text_edits(
    value: str, *, raw: bool = True, labels: frozenset[int] | None = None
) -> Iterator[tuple[int, int, str]]:
    """Credential spans; ``labels``, when given, are the starts of secret label tokens."""
    for pattern in (_BEARER_TOKEN, _BASIC_TOKEN):
        for match in pattern.finditer(value):
            yield match.start(1), match.end(1), _REDACTED
    # Enclosing assignments see their complete values before URL protection.
    # Names within standalone URLs are handled separately, preserving authority.
    yield from _named_value_edits(value, protect_urls=True, empty_values=not raw, labels=labels)
    # Matches are ordered, so each lookahead is found once per position. An '@'
    # after another scheme or on another line belongs to something else.
    following = _NextFinder(value)
    token_end = -1
    for match in _URL.finditer(value):
        end = match.end()
        if end < len(value) and value[end] in "\"'<>":
            if token_end < end:
                token_end = _token_end(value, end)
            boundary = min(following("://", end), following("\n", end))
            # A quote or angle bracket ended the URL inside a token, so a query
            # value or userinfo may continue past it: withhold through the token.
            if _truncated_url(match.group(), following("@", end) < min(token_end, boundary)):
                yield match.start(), token_end, _REDACTED
                continue
            # Cut inside the authority with an '@' starting a later token on the
            # line: the userinfo runs on across whitespace up to that '@'.
            spaced_at = following(_SPACED_AT, end)
            if "/" not in match.group()[match.group().index("://") + 3 :] and spaced_at < boundary:
                yield match.start(), spaced_at, _REDACTED
                continue
        # Only spaces (any Unicode space) between an authority and '@': the
        # authority is userinfo cut from its '@', as for the quoted case above.
        authority = match.start() + match.group().index("://") + 3
        if _SPACED_USERINFO.match(value, end) is not None and not _AUTHORITY_END.search(
            value, authority, end
        ):
            yield authority, end, _REDACTED
        for start, end, replacement in _url_edits(match.group(), raw=raw, labels=labels, at=match.start()):
            yield match.start() + start, match.start() + end, replacement
    yield from _jwt_edits(value)
    for match in _SECRET_VALUE.finditer(value):
        yield match.start(), match.end(), _REDACTED


def _union_edits(edits: Iterable[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for start, end, replacement in sorted(edits):
        # Adjacent replacements merge, so a second pass sees one token.
        if result and start <= result[-1][1]:
            result[-1] = result[-1][0], max(end, result[-1][1]), _REDACTED
        else:
            result.append((start, end, replacement))
    return result


def _literal_spans(value: str) -> Iterator[tuple[int, int]]:
    """Retained raw ranges when removed runs keep their printable bytes.

    Only escape framing and controls go: CSI parameters and final bytes, OSC
    payloads and the byte after a bare ESC read as literal text.
    """
    cursor = 0
    for start, end in (*control_free_spans(value), (len(value), len(value))):
        yield from _printable_spans(value, cursor, start)
        if start < end:
            yield start, end
        cursor = end


def _normalized_view(value: str, *, literal: bool = False) -> tuple[str, list[tuple[int, int]] | None]:
    """Detection text and one raw range per character; never a display value.

    Ranges are built in source order, so they are non-decreasing. Stripped
    controls, escape sequences and invisibles have no normalized character;
    the ``literal`` view keeps the printable bytes of escape sequences.
    """
    pieces: list[str] = []
    origins: list[tuple[int, int]] = []
    spans = list(_literal_spans(value) if literal else control_free_spans(value))
    for start, end in spans:
        for index in range(start, end):
            piece = normalize_text(value[index])
            pieces.append(piece)
            origins.extend([(index, index + 1)] * len(piece))
    normalized = normalize_text("".join(value[start:end] for start, end in spans))
    # Cross-character composition/reordering has no per-codepoint mapping.
    # Withhold recognized credentials rather than guess their source offsets.
    return normalized, origins if "".join(pieces) == normalized else None


def _structural(char: str) -> bool:
    return char.isspace() or char in "\"'=: /@?#[]\\,;&"


class _RawMap:
    """Map normalized detection spans to whole raw spans of one field."""

    def __init__(
        self, value: str, normalized: str, origins: list[tuple[int, int]], *, literal: bool = False
    ) -> None:
        self.value = value
        self.literal = literal
        self.normalized = normalized
        self.origins = origins
        self.starts = [start for start, _ in origins]
        self.retained = bytearray(len(value))
        for start in self.starts:
            self.retained[start] = 1
        self.raw_delimiters = [index for index, char in enumerate(value) if _structural(char)]
        self.normalized_delimiters = [
            (char, origin[0]) for char, origin in zip(normalized, origins, strict=True) if _structural(char)
        ]
        self.delimiter_starts = [start for _, start in self.normalized_delimiters]

    def secret_labels(self, budget: _Budget) -> frozenset[int]:
        """Starts of normalized name tokens whose raw label is secret.

        A token's raw label extends over removed bytes on either side, which a
        reading may take literally (``pa ESC [ ssword`` detects as ``pasword``),
        so it is judged by ``_is_secret_name`` on those raw bytes. In the
        literal view that raw judgment is the only one: the detection text of
        ``ESC [ 1m tokens ESC [ 0m`` is not a label the raw field carries.
        """
        labels: set[int] = set()
        length = len(self.value)
        for name in _NAME_TOKEN.finditer(self.normalized):
            start, end = self.origins[name.start()][0], self.origins[name.end() - 1][1]
            while start and not self.retained[start - 1]:
                start -= 1
            while end < length and not self.retained[end]:
                end += 1
            if all(self.retained[start:end]):
                secret = _is_secret_name(name.group())
            else:
                secret = (not self.literal and _is_secret_name(name.group())) or _is_secret_name(
                    self.value[start:end], budget
                )
            if secret:
                labels.add(name.start())
        return frozenset(labels)

    def span(self, start: int, end: int) -> tuple[int, int] | None:
        """Raw span from the previous to the next retained character, or None.

        Raw bytes that normalization removed next to a match (controls, escape
        sequences, invisibles) belong to the match: a value runs from just
        after its raw delimiter to just before its raw terminator. A boundary
        that splits one raw character's expansion has no raw position.
        """
        origins = self.origins
        if any(0 < edge < len(origins) and origins[edge - 1] == origins[edge] for edge in (start, end)):
            return None
        raw_start = origins[start - 1][1] if start else 0
        # Whitespace between a delimiter and its value is not a raw boundary
        # when removed bytes sit inside it: start just after the delimiter.
        previous = start - 1
        while previous >= 0 and self.normalized[previous].isspace():
            previous -= 1
        delimiter_end = origins[previous][1] if previous >= 0 else 0
        if not all(self.retained[delimiter_end:raw_start]):
            raw_start = delimiter_end
        return raw_start, origins[end][0] if end < len(origins) else len(self.value)

    def snap(self, start: int, end: int) -> tuple[int, int]:
        """Widen a raw span over removed bytes on either side.

        A raw terminator inside a removed escape sequence is not a terminator:
        the value continues after the sequence, until a retained terminator.
        """
        before = bisect_left(self.starts, start)
        length = len(self.value)
        while end < length and not self.retained[end]:
            after = bisect_left(self.starts, end)
            end = self.starts[after] if after < len(self.starts) else length
            if (match := _VALUE_CONTINUATION.match(self.value, end)) is not None:
                end = match.end()
        return self.origins[before - 1][1] if before else 0, end

    def ambiguous(self, start: int, end: int) -> bool:
        """Normalization moved, created or removed a delimiter in the span or at its end.

        Removed bytes after the span's last retained character are replaced
        with it and cannot extend the value; the terminator after them is checked.
        """
        following = bisect_left(self.starts, end)
        core_end = (
            self.origins[following - 1][1] if following and self.starts[following - 1] >= start else start
        )
        raw = self.raw_delimiters[
            bisect_left(self.raw_delimiters, start) : bisect_left(self.raw_delimiters, core_end)
        ]
        normalized = self.normalized_delimiters[
            bisect_left(self.delimiter_starts, start) : bisect_left(self.delimiter_starts, core_end)
        ]
        if [(self.value[index], index) for index in raw] != normalized:
            return True
        # The raw character that terminates the span must terminate it in both views.
        if following == len(self.starts):
            return False
        index = self.starts[following]
        char = self.value[index]
        return index != end or (normalize_text(char) != char and any(map(_structural, normalize_text(char))))


def _redaction_edits(
    value: str, raw_edits: list[tuple[int, int, str]] | None = None
) -> list[tuple[int, int, str]] | None:
    """Disjoint raw-span edits for one field, or None to withhold the whole field.

    Normalization is for detection only. Every normalized match is mapped to a
    whole raw span and the union of raw spans is replaced; no normalized text
    or normalized offset is ever emitted. ``raw_edits`` may carry the field's
    already computed raw-pass union.
    """
    if raw_edits is None:
        raw_edits = _union_edits(_text_edits(value))
    normalized = normalize_text(strip_controls(value))
    if normalized == value:
        return raw_edits
    budget = _Budget(len(value))
    edits = _view_edits(value, raw_edits, budget, literal=False)
    # A removed run may have consumed printable bytes (a CSI final byte, an
    # ESC-swallowed ':', an OSC payload): detect against that reading too.
    if edits is None or not any(_RUN_FRAMING.sub("", run) for run in _removed_runs(value)):
        return edits
    literal = _view_edits(value, raw_edits, budget, literal=True, covered=edits)
    if literal is None:
        return None
    # Mixed readings (one run dropped, another literal) and the decisions they
    # change (flag, delimiter, label) are checked token by token.
    return _union_edits([*edits, *literal, *_token_reading_edits(value, budget)])


def _reading_outcome(
    value: str, window: list[_Segment], in_run: bytearray, budget: _Budget, suffix: str = ""
) -> tuple[list[tuple[int, int, str]], bool] | None:
    """Detect a window of raw text in every reading of its removed runs.

    Each reading is detected like any field: names are judged by
    ``_is_secret_name`` on their raw extent (adjacent removed runs included),
    so a flag, label, delimiter or userinfo decision is made over the same
    readings everywhere. Matches map back to raw spans widened over removed
    runs. The boolean reports whether a match reached into ``suffix`` (text
    after the window). None when the readings cannot be enumerated within the
    field's remaining ``budget`` or have no per-character raw map.
    """
    start, end = window[0].start, window[-1].end
    # Charge the whole window per reading before building any of them.
    count = _reading_count(window)
    if count > _MAX_READINGS:
        return None
    readings = _readings(window) if budget.charge(count * (end - start)) else None
    if readings is None:
        return None

    def widen(left: int, right: int) -> tuple[int, int]:
        while left > start and in_run[left - 1]:
            left -= 1
        while right < end and in_run[right]:
            right += 1
        return left, right

    edits: list[tuple[int, int, str]] = []
    claims = False
    for reading in readings:
        if not any(reading.literal):
            continue  # The detection views already read every run as dropped.
        pieces = [normalize_text(char) for char in reading.text]
        text = "".join(pieces)
        if text != normalize_text(reading.text):
            return None
        origins = [origin for piece, origin in zip(pieces, reading.origins, strict=True) for _ in piece]
        labels: set[int] = set()
        for name in _NAME_TOKEN.finditer(text):
            left, right = widen(origins[name.start()], origins[name.end() - 1] + 1)
            if _is_secret_name(value[left:right], budget):
                labels.add(name.start())
        length = len(text)
        for left, right, _ in _text_edits(text + suffix, raw=False, labels=frozenset(labels)):
            claims = claims or right > length
            right = min(right, length)
            if left < right:
                edits.append((*widen(origins[left], origins[right - 1] + 1), _REDACTED))
    return edits, claims


def _run_mask(value: str, segments: list[_Segment]) -> bytearray:
    in_run = bytearray(len(value))
    for segment in segments:
        if segment.choices[0][2]:
            in_run[segment.start : segment.end] = b"\x01" * (segment.end - segment.start)
    return in_run


def _joinable(chunk: list[_Segment]) -> bool:
    """Only escape sequences and delimiters: a label may continue across it to a value."""
    return all(
        segment.choices[0][2] or set(normalize_text(segment.choices[0][0])) <= {":", "="} for segment in chunk
    )


def _joined(value: str, chunks: list[list[_Segment]]) -> list[_Segment]:
    """Consecutive chunks as one window, the raw whitespace between them retained."""
    window = list(chunks[0])
    for chunk in chunks[1:]:
        gap = (value[window[-1].end : chunk[0].start], tuple(range(window[-1].end, chunk[0].start)), False)
        window += [_Segment(window[-1].end, chunk[0].start, (gap,)), *chunk]
    return window


def _token_reading_edits(value: str, budget: _Budget) -> Iterator[tuple[int, int, str]]:
    """Raw spans that some reading of the removed runs makes a credential.

    Decisions span neighbouring tokens (a flag and its value, a label and the
    value after ': ', an authority and a spaced '@host'), so each
    whitespace-free token is read together with the tokens up to the next one
    that is more than escape sequences and delimiters: a delimiter supplied by
    an escape may stand alone between a label and its value. A window that
    cannot be enumerated (too many readings or joined tokens, an over-long
    sequence, the field's budget spent, or no per-character map) is withheld
    whole: no cheaper test is as conservative as the readings it skips.
    """
    segments = _segments(value)
    in_run = _run_mask(value, segments)
    chunks = [chunk for chunk in _chunks(segments) if chunk]
    varied = list(
        accumulate((any(len(segment.choices) > 1 for segment in chunk) for chunk in chunks), initial=0)
    )
    # solid[k]: the first chunk at or after k that is not joinable.
    solid = [len(chunks)] * (len(chunks) + 1)
    for index in range(len(chunks) - 1, -1, -1):
        solid[index] = solid[index + 1] if _joinable(chunks[index]) else index
    for index, chunk in enumerate(chunks):
        last = min(solid[min(index + 1, len(chunks))], len(chunks) - 1)
        if varied[last + 1] == varied[index]:
            continue
        start, end = chunk[0].start, chunks[last][-1].end
        outcome = (
            _reading_outcome(value, _joined(value, chunks[index : last + 1]), in_run, budget)
            if last - index - 1 <= _MAX_JOINED
            else None
        )
        if outcome is None:
            outcome = [(start, end, _REDACTED)], False
        for left, right, replacement in outcome[0]:
            if right == end:
                # A value the window cut short continues as one value, from
                # its first retained character or the window's last token.
                for first in (left, chunks[last][0].start):
                    while first < right and in_run[first]:
                        first += 1
                    if first >= left and (match := _VALUE_CONTINUATION.match(value, first)) is not None:
                        right = max(right, match.end())
            yield left, right, replacement


def _claims_next_argument(item: str) -> bool:
    """Some reading of an argument takes the next argument as its value (assumed when unenumerable)."""
    segments = _segments(item)
    if not any(len(segment.choices) > 1 for segment in segments):
        return False
    budget = _Budget(len(item), _LABEL_WORK_FLOOR)
    outcome = _reading_outcome(item, segments, _run_mask(item, segments), budget, " v")
    return outcome is None or outcome[1]


def _removed_runs(value: str) -> Iterator[str]:
    cursor = 0
    for start, end in (*control_free_spans(value), (len(value), len(value))):
        if cursor < start:
            yield value[cursor:start]
        cursor = end


def _view_edits(
    value: str,
    raw_edits: list[tuple[int, int, str]],
    budget: _Budget,
    *,
    literal: bool,
    covered: list[tuple[int, int, str]] | None = None,
) -> list[tuple[int, int, str]] | None:
    """Raw-span edits from one detection view of the field, or None to withhold it.

    An ambiguous extent inside a ``covered`` edit (another view's) is replaced anyway.
    """
    normalized, origins = _normalized_view(value, literal=literal)
    if origins is None:
        return None
    raw_map = _RawMap(value, normalized, origins, literal=literal)
    labels = raw_map.secret_labels(budget)
    normalized_edits = list(_text_edits(normalized, raw=False, labels=labels))
    raw_edits = _union_edits(
        (*raw_map.snap(start, end), replacement) for start, end, replacement in raw_edits
    )
    edits = list(raw_edits)
    for url in _URL.finditer(normalized):
        span = raw_map.span(url.start(), url.end())
        if span is None:
            return None
        # Judge the URL by its own raw characters; replace it with its neighbors.
        if _ambiguous_url(value[origins[url.start()][0] : origins[url.end() - 1][1]]):
            edits.append((*span, _REDACTED))
    for start, end, replacement in normalized_edits:
        span = raw_map.span(start, end)
        if span is None:
            return None
        if start < end or span[0] < span[1]:
            edits.append((*span, replacement))
        # An empty detection match hides only raw bytes removed at its position;
        # a terminator that normalization created there leaves no raw extent.
        elif raw_map.ambiguous(*span) and not any(
            left <= span[0] < right for left, right, _ in (*raw_edits, *(covered or ()))
        ):
            return None
    result = _union_edits(edits)
    for start, end, _ in result:
        if not raw_map.ambiguous(start, end) or any(
            left <= start and end <= right for left, right, _ in covered or ()
        ):
            continue
        # A complete raw value (snapped to retained characters) is withheld in
        # place; any other ambiguous extent withholds the field.
        if value[start:end].isascii() and any(left <= start and end <= right for left, right, _ in raw_edits):
            continue
        return None
    # These spans end at raw whitespace, so they need no ambiguity check.
    swallowed = list(_swallowed_delimiter_edits(raw_map, result, labels, budget))
    return _union_edits([*result, *swallowed]) if swallowed else result


_SWALLOWABLE = frozenset("=:@\"'/?#&;,")


def _secret_names(text: str, labels: frozenset[int] | None = None) -> tuple[list[int], dict[int, int]]:
    """Starts of secret label words, and each one's start keyed by its end."""
    names = [
        name
        for name in _NAME_TOKEN.finditer(text)
        if (name.start() in labels if labels is not None else _is_secret_name(name.group()))
    ]
    return [name.start() for name in names], {name.end(): name.start() for name in names}


def _after_last(positions: list[int], limit: int) -> int:
    """Index just after the last listed position before ``limit`` (a token start)."""
    index = bisect_left(positions, limit)
    return positions[index - 1] + 1 if index else 0


def _swallowed_delimiter_edits(
    raw_map: _RawMap, result: list[tuple[int, int, str]], labels: frozenset[int], budget: _Budget
) -> Iterator[tuple[int, int, str]]:
    """Removed bytes may never hide a delimiter next to a credential.

    For each run of raw bytes that detection removed: if it holds a structural
    delimiter, ends in a bare two-byte escape (whose extent terminals read
    differently), is itself a secret label when read literally and directly
    precedes an assignment, or directly follows a secret label word, withhold from the
    first secret label or URL in its whitespace-free token (or a raw label
    inside the run) through the end of that token. A run inside an existing
    replacement only matters for the first two reasons, which can end it
    early; that replacement then extends through the token, keeping its
    intact raw label.
    """
    value, normalized, starts = raw_map.value, raw_map.normalized, raw_map.starts
    normalized_names, normalized_ends = _secret_names(normalized, labels)
    raw_names, raw_ends = _secret_names(value)
    normalized_spaces = [index for index, char in enumerate(normalized) if char.isspace()]
    raw_spaces = [index for index, char in enumerate(value) if char.isspace()]
    schemes = [match.start() for match in re.finditer("://", normalized)]
    covered = [start for start, _, _ in result]
    index, length = 0, len(value)
    while index < length:
        if raw_map.retained[index]:
            index += 1
            continue
        run_start = index
        while index < length and not raw_map.retained[index]:
            index += 1
        run = value[run_start:index]
        following = bisect_left(starts, run_start)
        # An OSC payload, say, that reads as a label for the assignment after it.
        label = _ASSIGNMENT_PREFIX.match(normalized, following) is not None and _is_secret_name(run, budget)
        delimiter = (
            label
            or any(char.isspace() or char in _SWALLOWABLE for char in run)
            or (len(run) >= 2 and run[-2] == "\x1b" and run[-1] not in "[]")
        )
        edit = bisect_left(covered, run_start + 1) - 1
        inside = edit >= 0 and index <= result[edit][1]
        if not delimiter and (inside or (following not in normalized_ends and run_start not in raw_ends)):
            continue
        if inside:
            # The label and delimiter before this replacement are intact raw
            # text; only its end is in doubt, so extend it through the token.
            yield result[edit][0], _token_end(value, index), _REDACTED
            continue
        token_start = _after_last(normalized_spaces, following)
        raw_token_start = _after_last(raw_spaces, run_start)
        anchors: list[int] = []
        name = bisect_left(normalized_names, token_start)
        if name < len(normalized_names) and normalized_names[name] < following:
            anchors.append(raw_map.origins[normalized_names[name]][0])
        scheme = bisect_left(schemes, token_start)
        if scheme < len(schemes) and schemes[scheme] < following:
            anchors.append(raw_map.origins[token_start][0])
        name = bisect_left(raw_names, raw_token_start)
        # A raw label inside the removed run counts too (an OSC payload, say).
        if name < len(raw_names) and raw_names[name] < index:
            anchors.append(raw_names[name])
        if label:
            anchors.append(run_start)
        if anchors:
            yield min(anchors), _token_end(value, index), _REDACTED


def redact_text(value: str) -> str:
    """Redact text, reusing bounded short fields only within a report operation."""
    cached = _REPORT_REDACTOR.get()
    return cached(value) if cached is not None and len(value) <= 1024 else _redact_text(value)


def _redact_text(value: str) -> str:
    """Redact likely credential values while preserving useful context.

    Each pass replaces whole raw spans, so its output is still the raw field
    with spans replaced. Replacing a value can change how neighboring
    detectors read the field (a removed '//' ends a URL), so passes repeat
    until the output is stable; a field that does not settle is withheld.
    """
    for _ in range(_MAX_PASSES):
        edits = _redaction_edits(value)
        if edits is None:
            return _REDACTED
        redacted = _apply_edits(value, edits)
        if redacted == value:
            return value
        value = redacted
    return _REDACTED


def _normalization_exposes_secret(redacted: str) -> bool:
    # normalize_text is the identity on ASCII (test_normalize_text_is_identity_on_ascii).
    normalized = strip_controls(redacted)
    if not normalized.isascii():
        normalized = normalize_text(normalized)
    return (
        normalized != redacted
        and _apply_edits(normalized, _union_edits(_text_edits(normalized, raw=False))) != normalized
    )


def trim_excerpt_context(before: str, after: str) -> tuple[str, str]:
    """Remove an outer context token, clearing whitespace-only context too."""
    if before:
        before = "" if before.isspace() else re.sub(r"^\s*\S+\s*", "", before, count=1)
    elif after:
        after = "" if after.isspace() else re.sub(r"\s*\S+\s*$", "", after, count=1)
    return before, after


def redacted_excerpt(
    text: str,
    start: int,
    end: int,
    *,
    context_before: int = 0,
    context_after: int = 0,
    max_length: int | None = None,
    word_boundaries: bool = False,
    mark_match: bool = False,
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
    raw_edits = _union_edits(_text_edits(text))
    redacted = _apply_edits(text, raw_edits, window)
    # A label or value extent can become recognizable only after Unicode
    # normalization or control stripping. If raw-field redaction is not the
    # complete field redaction, withhold the field's evidence altogether
    # rather than copy any raw or normalized part of that value.
    if (
        _redaction_edits(text, raw_edits) != raw_edits
        or (raw_edits and redact_text(redacted) != redacted)
        or _normalization_exposes_secret(redacted)
    ):
        withheld = "[metadata excerpt withheld]"
        return withheld if max_length is None else withheld[:max_length]
    left = max(0, window.start - context_before)
    right = min(len(redacted), window.end + context_after)
    if word_boundaries:
        while (
            context_before > 0
            and left > 0
            and not redacted[left - 1].isspace()
            and not redacted[left].isspace()
        ):
            left -= 1
        while (
            context_after > 0
            and right < len(redacted)
            and not redacted[right - 1].isspace()
            and not redacted[right].isspace()
        ):
            right += 1

    def render(piece: str) -> str:
        rendered = render_invisibles(piece)
        # Source text cannot forge the delimiters used to carry match offsets.
        if mark_match:
            rendered = rendered.replace("⟦", "‹U+27E6›").replace("⟧", "‹U+27E7›")
        return rendered

    before = render(redacted[left : window.start])
    match = render(redacted[window.start : window.end])
    after = render(redacted[window.end : right])
    if mark_match and match:
        match = f"⟦{match}⟧"
    if word_boundaries and max_length is not None:
        if len(match) > max_length:
            return "[match exceeds excerpt limit]"[:max_length]
        # Keep the entire match; trim context a token at a time, including
        # rendered invisible markers, rather than cutting through a word.
        while len(before) + len(match) + len(after) > max_length:
            before, after = trim_excerpt_context(before, after)
        return before + match + after
    if max_length is not None:
        # Expanded invisible markers must not push the actual match out of view.
        if len(before) + len(match) > max_length:
            before = ""
        return (before + match + after)[:max_length]
    return before + match + after


def marked_excerpt_parts(excerpt: str) -> tuple[str, tuple[int, int] | None]:
    """Separate helper-owned delimiters into plain evidence and display offsets."""
    before, delimiter, rest = excerpt.partition("⟦")
    if not delimiter:
        return excerpt, None
    match, delimiter, after = rest.partition("⟧")
    if not delimiter:
        raise ValueError("Unclosed match delimiter in redacted excerpt")
    return before + match + after, (len(before), len(before) + len(match))


def _redact_literal_strings(value: object) -> object:
    """Hide string literals in secret-property defaults/examples/const, retaining shape."""
    if isinstance(value, str):
        return _REDACTED
    if isinstance(value, list):
        return [_redact_literal_strings(item) for item in value]
    if isinstance(value, dict):
        result: dict[object, object] = {}
        for key, item in value.items():
            result[_redacted_key(key, result)] = _redact_literal_strings(item)
        return result
    return value


def _redacted_key(key: object, result: dict[object, object]) -> object:
    """Scrub dynamic keys without losing entries when multiple secrets collapse."""
    redacted = redact_text(key) if isinstance(key, str) else key
    candidate = redacted
    index = 2
    while candidate in result:
        candidate = f"{redacted} [{index}]"
        index += 1
    return candidate


def _redact_properties(
    properties: dict[object, object], *, secret_schema: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for name, schema in properties.items():
        result[_redacted_key(name, result)] = _redact_json(
            schema, secret_schema=secret_schema or (isinstance(name, str) and _is_secret_name(name))
        )
    return result


def redact_argv(value: list[object]) -> list[object]:
    """Use argv boundaries, including values that start with a dash."""
    result: list[object] = []
    secret_value = False
    for item in value:
        if secret_value:
            result.append(_REDACTED)
            secret_value = False
            continue
        if not isinstance(item, str):
            result.append(_redact_json(item))
            continue
        normalized, origins = _normalized_view(item)
        name = _NAME_TOKEN.match(normalized)
        if (
            name is not None
            and normalized[name.end() :].startswith(("=", ":"))
            # The raw label runs up to the raw delimiter, removed bytes included.
            and _is_secret_name(name.group() if origins is None else item[: origins[name.end()][0]])
            and _URL.match(normalized) is None
        ):
            # Cut the raw argument just after the raw delimiter character and
            # replace the whole remaining value, including removed controls.
            # A delimiter that shares its raw character with a neighbor has no
            # raw boundary, so the argument is withheld.
            delimiter = name.end()
            if origins is None or any(
                0 <= neighbor < len(origins) and origins[neighbor] == origins[delimiter]
                for neighbor in (delimiter - 1, delimiter + 1)
            ):
                result.append(_REDACTED)
            else:
                result.append(redact_text(item[: origins[delimiter][1]] + _REDACTED))
        else:
            result.append(redact_text(item))
        secret_value = (
            normalized.startswith("-")
            and _NAME_TOKEN.fullmatch(normalized) is not None
            and _is_secret_name(item)
        ) or _claims_next_argument(item)
    return result


def redact_url(value: str) -> str:
    """Parse a complete URL field; retain endpoint shape, never authentication data."""
    # A field the free-text URL span would not cover whole has no raw boundary.
    if _ambiguous_url(value) or _URL_VALUE.fullmatch(value) is None:
        return _REDACTED
    # Work on raw spans, retaining the exact spelling and delimiters of the URL.
    return redact_text(value)


def _redact_json(value: object, *, secret_schema: bool = False) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_json(item, secret_schema=secret_schema) for item in value]
    if isinstance(value, dict):
        result: dict[object, object] = {}
        for key, item in value.items():
            redacted: object
            # Secret-property context follows composition branches, while the
            # usual metadata rules still apply to non-literal fields.
            if secret_schema and key in {"default", "example", "examples", "const", "enum"}:
                redacted = _redact_literal_strings(item)
            elif key == "properties" and isinstance(item, dict):
                redacted = _redact_properties(item, secret_schema=secret_schema)
            elif key == "config_pointer" and isinstance(item, str):
                redacted = _redact_config_pointer(item)
            elif key == "args" and isinstance(item, list):
                redacted = redact_argv(item)
            elif key in {"env", "headers"} and isinstance(item, dict):
                key_map: dict[object, object] = {}
                for name in item:
                    key_map[_redacted_key(name, key_map)] = _REDACTED
                redacted = key_map
            elif isinstance(key, str) and _is_secret_name(key):
                redacted = _redact_literal_strings(item)
            else:
                redacted = _redact_json(item, secret_schema=secret_schema)
            result[_redacted_key(key, result)] = redacted
        return result
    return value


def redact_data(value: Any) -> Any:
    """Redact JSON-like metadata; retain the legacy top-level argv-list API."""
    return redact_argv(value) if isinstance(value, list) else _redact_json(value)


def redact_model(model: BaseModel) -> dict[str, object]:
    """One structural pass over a typed report, preserving declared field names."""
    from mcp_audit.models import ServerConfig

    def walk(source: object, data: object) -> object:
        # These containers belong to model_dump, not the caller's model.
        if isinstance(source, BaseModel) and isinstance(data, dict):
            matched_text = data.get("matched_text")
            for key, item in data.items():
                if isinstance(source, ServerConfig) and key == "args" and isinstance(item, list):
                    data[key] = redact_argv(item)
                elif isinstance(source, ServerConfig) and key == "url" and isinstance(item, str):
                    data[key] = redact_url(item)
                elif key == "config_pointer" and isinstance(item, str):
                    data[key] = _redact_config_pointer(item)
                else:
                    data[key] = walk(getattr(source, key), item)
            if data.get("matched_span") is not None and data.get("matched_text") != matched_text:
                data["matched_span"] = None
            return data
        if isinstance(source, (list, tuple)) and isinstance(data, list):
            for index, (raw, item) in enumerate(zip(source, data, strict=True)):
                data[index] = walk(raw, item)
            return data
        if (
            isinstance(source, dict)
            and isinstance(data, dict)
            and any(isinstance(item, BaseModel) for item in source.values())
        ):
            result_map: dict[object, object] = {}
            for key, item in data.items():
                result_map[_redacted_key(key, result_map)] = walk(source[key], item)
            return result_map
        return _redact_json(data)

    # Repeated schema words and evidence are common in large fleets. The cache
    # belongs to this operation, so raw credential-bearing text is not retained.
    cached = lru_cache(maxsize=4096)(_redact_text)
    token = _REPORT_REDACTOR.set(cached)
    try:
        data = walk(model, model.model_dump(mode="json"))
    finally:
        _REPORT_REDACTOR.reset(token)
        cached.cache_clear()
    assert isinstance(data, dict)
    return data


def _redact_config_pointer(pointer: str) -> str:
    """Redact credentials inside each JSON Pointer token, which ``~1`` escaping hides."""
    return "/".join(
        redact_text(token.replace("~1", "/").replace("~0", "~")).replace("~", "~0").replace("/", "~1")
        for token in pointer.split("/")
    )


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
        scrubbed = {
            key: _scrub_config_pointer(item, hostname, name_aliases, alias_pattern)
            if key == "config_pointer" and isinstance(item, str)
            else _walk_identifiers(item, hostname, name_aliases, alias_pattern)
            for key, item in value.items()
        }
        # Offsets index the original matched_text; drop them once its text changes.
        if scrubbed.get("matched_span") is not None and scrubbed.get("matched_text") != value.get(
            "matched_text"
        ):
            scrubbed["matched_span"] = None
        return scrubbed
    return value


def _scrub_config_pointer(
    pointer: str,
    hostname: str | None,
    name_aliases: dict[str, str] | None,
    alias_pattern: re.Pattern[str] | None,
) -> str:
    tokens = pointer.split("/")
    for index, token in enumerate(tokens):
        # Map keys are structural; only the final name and project path carry identifiers.
        if index != len(tokens) - 1 and not (index == 2 and tokens[1] == "projects"):
            continue
        # Decode in this order so a literal ~1 (encoded as ~01) stays literal.
        decoded = token.replace("~1", "/").replace("~0", "~")
        scrubbed = (
            name_aliases[decoded]
            if name_aliases is not None and decoded in name_aliases
            else _scrub_identifier_text(decoded, hostname, name_aliases, alias_pattern)
        )
        tokens[index] = scrubbed.replace("~", "~0").replace("/", "~1")
    return "/".join(tokens)
