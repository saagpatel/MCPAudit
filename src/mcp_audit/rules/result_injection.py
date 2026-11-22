"""Instruction-shaped tool-result rules; findings never retain result excerpts.

Heuristics, not a semantic verdict. Keep all runtime-result phrases here.

The credential hunt is evaluated in two stages so cost stays linear in the
scanned text: one pass locates candidate targets, then a bounded look-back
(never across a sentence boundary) checks for a directing verb. Concrete
secret paths and names are strong evidence on their own; generic nouns such
as "credentials" or "API keys" also need an agent-directed frame.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Scanned text per result is capped; the caller reports the truncation.
RESULT_SCAN_LIMIT = 64 * 1024
_LOOKBACK = 160
_LOOKAHEAD = 80

_VERBS = (
    r"\b(?:include|get|fetch|upload|copy|paste|attach|share|send|read|cat|open|collect|retrieve"
    r"|print|dump|inspect|access|extract|list|output|return|pass|append|export|reveal|show|echo"
    r"|display|forward|post|transmit|exfiltrate|grab)\b"
)
# Bare ".env" is a filename convention, not a path; only an outbound verb
# makes it a hunt (reading it during setup is ordinary developer text). The
# verb may come before the file, or after it when a verb takes the file as its
# object ("Read .env and send it", "Do not print .env, upload it instead"). A
# negated verb ("never send") is guidance, not a hunt; the negation carries
# only to verbs coordinated directly with it by "and", "or" or "nor" ("Never
# read .env and send it"), never into a new clause ("Do not print .env,
# instead read it and send it").
_EXFIL_VERBS = (
    r"\b(?:include|upload|paste|attach|share|send|cat|print|dump|output|return|export|reveal"
    r"|show|echo|display|forward|post|transmit|exfiltrate)\b"
)
_HOME = r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/root|/(?:Users|home)/[^/\s]+)"
# Concrete secret locations and names. "~/.ssh/config" is host-alias
# configuration rather than key material and is excluded explicitly.
_CONCRETE_TARGET = re.compile(
    rf"(?:{_HOME}[\\/]\.(?:ssh\b(?![\\/]config\b)|aws[\\/](?:credentials|config)\b|kube[\\/]config\b"
    r"|netrc\b|git-credentials\b|npmrc\b|pypirc\b|docker[\\/]config\.json\b"
    r"|config[\\/]gh[\\/]hosts\.yml\b|cursor[\\/]mcp\.json\b|env\b(?!\.(?:example|sample|template|dist)\b)"
    r"|[a-z]*_?history\b)"
    r"|(?<![\w/\\.])\.(?:ssh[\\/](?!config\b)[\w.-]+|aws[\\/]credentials|kube[\\/]config|netrc|git-credentials"
    r"|[a-z]*_?history)\b"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bkubeconfig\b"
    r"|(?-i:\b(?:GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN"
    r"|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|SLACK_TOKEN|DATABASE_URL)\b)"
    r"|(?-i:\$\{?(?:[A-Z_][A-Z0-9_]*_)?(?:TOKEN|SECRET|API_KEY|PASSWORD|CREDENTIALS)\}?)"
    r"|\b(?:os\.environ|process\.env|environment\s+variables?|env\s+vars?|shell\s+history)\b)",
    re.IGNORECASE,
)
_DOTENV_TARGET = re.compile(r"(?<![\w/\\.])\.env\b(?!\.(?:example|sample|template|dist)\b)", re.IGNORECASE)
_GENERIC_TARGET = re.compile(
    r"\b(?:credentials?|api(?:[_-]|\s+)?keys?|secrets?|passwords?"
    r"|(?:access|auth|api|bearer|secret|refresh)\s+tokens?)\b",
    re.IGNORECASE,
)
# A sentence boundary ends the look-back; dots inside paths do not.
_SENTENCE_BOUNDARY = re.compile(r"[\n!?;]|\.(?=\s|$)")
# Greedy prefix up to the last boundary in a window (windows are at most 160 chars).
_THROUGH_LAST_BOUNDARY = re.compile(r".*(?:[\n!?;]|\.(?=\s|$))", re.DOTALL)
_VERB_RE = re.compile(_VERBS, re.IGNORECASE)
_EXFIL_VERB_RE = re.compile(_EXFIL_VERBS, re.IGNORECASE)
# A read or outbound verb whose object is the ".env" that follows (articles and
# possessives may intervene; "copy .env.example to .env" does not qualify).
_DOTENV_GOVERNED = re.compile(
    r"(?:\b(?:read|open|load|get|fetch|grab|collect|retrieve|extract|copy|access|parse|source|take)\b"
    rf"|{_EXFIL_VERBS})\s+"
    r"(?:(?:the|your|my|our|their|this|that|local|project|contents\s+of)\s+){0,4}[`'\"]?$",
    re.IGNORECASE,
)
# Negation immediately before a verb: "never send", "do not send", "don't ever send".
_NEGATED_BEFORE_VERB = re.compile(
    r"(?:\b(?:never|not|cannot|dont|without|avoid(?:ing)?)|n['\u2019]t)\s+(?:(?:ever|accidentally)\s+)?$",
    re.IGNORECASE,
)
# The whole gap between a negated verb's object and the next verb when that
# verb is directly coordinated with it, so the negation extends to it.
_COORDINATED = re.compile(
    r"[`'\"]?(?:\s+(?:files?|it|them))?\s*(?:,\s*)?(?:and|or|nor)\s+(?:then\s+)?", re.IGNORECASE
)
# Agent-directed frames immediately before the verb: a vocative or an obligation.
_DIRECTIVE_BEFORE_VERB = re.compile(
    r"(?:\b(?:assistant|agent|model|ai|claude)\s*[,:]?\s*"
    r"|\byou\s+(?:must|should|need\s+to|have\s+to|are\s+to|are\s+required\s+to|will\s+now|now\s+need\s+to)\s+"
    r"|\byour\s+(?:next\s+|first\s+)?(?:task|job|step|action)\s+is\s+to\s+)"
    r"(?:also\s+|now\s+|please\s+|then\s+)*$",
    re.IGNORECASE,
)
# Exfiltration destination after a generic noun: the agent's own output or another tool.
_DESTINATION_AFTER_NOUN = re.compile(
    r"\b(?:in|into|with|as|to|via|through)\s+(?:your\s+(?:next\s+|following\s+)?"
    r"(?:tool\s+call|response|answer|reply|message|output|request|argument|note)"
    r"|(?:the\s+|another\s+|other\s+)?[\w.-]+\s+tool)\b",
    re.IGNORECASE,
)
_AGENT = r"\b(?:you|assistant|agent|model)\b"
_NEAR = r"[^\n!?;]{0,160}?"
_REDIRECT = (
    r"\b(?:call|invoke|execute|use)\s+(?:the\s+)?(?:other\s+|another\s+)?"
    r"(?:[\w.-]+\s+)?tools?\b|\btools/call\b"
)
# Any run of whitespace separates phrase words, so doubled spaces, tabs and
# newlines do not split a phrase.
_INSTRUCTION_OVERRIDE = re.compile(
    r"\b(?:ignore\s+(?:(?:all|any|the|your)\s+)?(?:previous|prior|above)"
    r"|(?:disregard|forget)\s+(?:(?:all|any|the|your)\s+)?(?:previous|prior|above))\b",
    re.IGNORECASE,
)
_TOOL_REDIRECT = re.compile(
    rf"(?:{_AGENT}{_NEAR}(?:{_REDIRECT})"
    rf"|(?:^|[.!?;\n]\s*|\b(?:please|now|then|and)\s+)\s*(?:{_REDIRECT}))",
    re.IGNORECASE,
)


def _same_sentence_before(text: str, end: int) -> tuple[str, int]:
    """Return the bounded text before ``end`` since the last sentence boundary."""
    start = max(0, end - _LOOKBACK)
    window = text[start:end]
    boundary = _THROUGH_LAST_BOUNDARY.match(window)
    if boundary is not None:
        return window[boundary.end() :], start + boundary.end()
    return window, start


def _same_sentence_after(text: str, start: int) -> str:
    window = text[start : start + _LOOKAHEAD]
    boundary = _SENTENCE_BOUNDARY.search(window)
    return window[: boundary.start()] if boundary else window


def _frames_before(text: str, position: int, verbs: re.Pattern[str]) -> list[str]:
    """Same-sentence text preceding each directing verb found before ``position``."""
    window, _ = _same_sentence_before(text, position)
    return [window[: match.start()] for match in verbs.finditer(window)]


def _unnegated(window: str, verbs: re.Pattern[str]) -> bool:
    return any(not _NEGATED_BEFORE_VERB.search(window[: verb.start()]) for verb in verbs.finditer(window))


def dotenv_hunt(text: str, start: int, end: int) -> bool:
    """True when an outbound verb in the same sentence directs ``text[start:end]`` (a ".env")."""
    window, _ = _same_sentence_before(text, start)
    if _unnegated(window, _EXFIL_VERB_RE):
        return True
    governing = _DOTENV_GOVERNED.search(window)
    if governing is None:
        return False
    negated = _NEGATED_BEFORE_VERB.search(window[: governing.start()]) is not None
    after = _same_sentence_after(text, end)
    previous = 0
    for verb in _EXFIL_VERB_RE.finditer(after):
        if _NEGATED_BEFORE_VERB.search(after[: verb.start()]):
            negated = True
        elif not (negated and _COORDINATED.fullmatch(after, previous, verb.start())):
            return True
        previous = verb.end()
    return False


def credential_hunt(text: str) -> bool:
    """True when a verb directs the reader toward a secret path, name, or store."""
    for target in _CONCRETE_TARGET.finditer(text):
        if _frames_before(text, target.start(), _VERB_RE):
            return True
    for target in _DOTENV_TARGET.finditer(text):
        if dotenv_hunt(text, *target.span()):
            return True
    for target in _GENERIC_TARGET.finditer(text):
        frames = _frames_before(text, target.start(), _VERB_RE)
        if not frames:
            continue
        if _DESTINATION_AFTER_NOUN.search(_same_sentence_after(text, target.end())):
            return True
        if any(_DIRECTIVE_BEFORE_VERB.search(frame) for frame in frames):
            return True
    return False


RESULT_INJECTION_RULES: dict[str, Callable[[str], bool]] = {
    "result_instruction_override": lambda text: _INSTRUCTION_OVERRIDE.search(text) is not None,
    "result_credential_hunt": credential_hunt,
    "result_tool_redirect": lambda text: _TOOL_REDIRECT.search(text) is not None,
}
