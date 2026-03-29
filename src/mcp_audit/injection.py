"""Prompt injection detection — scan tool descriptions for adversarial patterns."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mcp_audit.models import InjectionFinding, InjectionSeverity, ToolInfo

# Unicode characters used for hidden directives
_ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d"}  # ZWSP, ZWNJ, ZWJ
_BIDI_OVERRIDE_CHARS = {
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
}

_ROLE_PREFIXES = ("assistant:", "human:", "user:", "\nassistant:", "\nhuman:", "\nuser:")


@dataclass
class _InjectionPattern:
    name: str
    severity: InjectionSeverity
    check: Callable[[str, str], bool]  # (lowercased_text, original_text) -> bool
    description: str
    _extract: Callable[[str, str], str]  # (lowercased_text, original_text) -> matched excerpt


def _phrase_check(phrases: list[str]) -> Callable[[str, str], bool]:
    def _check(lower: str, _orig: str) -> bool:
        return any(p in lower for p in phrases)

    return _check


def _phrase_extract(phrases: list[str]) -> Callable[[str, str], str]:
    def _extract(lower: str, orig: str) -> str:
        for phrase in phrases:
            idx = lower.find(phrase)
            if idx != -1:
                start = max(0, idx - 20)
                end = min(len(orig), idx + len(phrase) + 80)
                excerpt = orig[start:end]
                return excerpt[:200]
        return orig[:200]

    return _extract


def _unicode_check(chars: set[str]) -> Callable[[str, str], bool]:
    def _check(_lower: str, orig: str) -> bool:
        return any(c in orig for c in chars)

    return _check


def _unicode_extract(chars: set[str]) -> Callable[[str, str], str]:
    def _extract(_lower: str, orig: str) -> str:
        for c in chars:
            idx = orig.find(c)
            if idx != -1:
                start = max(0, idx - 10)
                end = min(len(orig), idx + 60)
                return f"[U+{ord(c):04X} at pos {idx}]: {orig[start:end]!r}"[:200]
        return orig[:200]

    return _extract


def _role_check(lower: str, _orig: str) -> bool:
    # Match at start of text, after newline, or after the first word (tool name prefix)
    for prefix in _ROLE_PREFIXES:
        clean = prefix.lstrip("\n")
        if lower.startswith(clean):
            return True
        # After any newline
        if f"\n{clean}" in lower:
            return True
        # At start of description portion — after "toolname " prefix
        space_idx = lower.find(" ")
        if space_idx != -1 and lower[space_idx + 1 :].startswith(clean):
            return True
    return False


def _role_extract(lower: str, orig: str) -> str:
    for prefix in _ROLE_PREFIXES:
        clean = prefix.lstrip("\n")
        idx = lower.find(clean)
        if idx != -1:
            start = max(0, idx)
            return orig[start : start + 200]
    return orig[:200]


_PATTERNS: list[_InjectionPattern] = [
    _InjectionPattern(
        name="ignore_instructions",
        severity=InjectionSeverity.HIGH,
        check=_phrase_check(
            [
                "ignore previous",
                "disregard all",
                "disregard previous",
                "forget everything",
                "ignore all previous",
            ]  # noqa: E501
        ),
        description="Tool description attempts to override AI instructions",
        _extract=_phrase_extract(
            [
                "ignore previous",
                "disregard all",
                "disregard previous",
                "forget everything",
                "ignore all previous",
            ]  # noqa: E501
        ),
    ),
    _InjectionPattern(
        name="system_override",
        severity=InjectionSeverity.HIGH,
        check=_phrase_check(["you are now", "new instructions:", "act as if you", "pretend you are"]),
        description="Tool description attempts to override AI role or system prompt",
        _extract=_phrase_extract(["you are now", "new instructions:", "act as if you", "pretend you are"]),
    ),
    _InjectionPattern(
        name="prompt_leak",
        severity=InjectionSeverity.HIGH,
        check=_phrase_check(
            [
                "repeat your system prompt",
                "reveal instructions",
                "show your instructions",
                "repeat everything above",
            ]
        ),
        description="Tool description attempts to extract the AI system prompt",
        _extract=_phrase_extract(
            [
                "repeat your system prompt",
                "reveal instructions",
                "show your instructions",
                "repeat everything above",
            ]
        ),
    ),
    _InjectionPattern(
        name="hidden_directive",
        severity=InjectionSeverity.MEDIUM,
        check=lambda lower, orig: "<!--" in lower or any(c in orig for c in _ZERO_WIDTH_CHARS),
        description="Tool description contains hidden content (HTML comments or zero-width characters)",
        _extract=lambda lower, orig: (
            _unicode_extract(_ZERO_WIDTH_CHARS)(lower, orig)
            if any(c in orig for c in _ZERO_WIDTH_CHARS)
            else orig[max(0, lower.find("<!--")) : max(0, lower.find("<!--")) + 200]
        ),
    ),
    _InjectionPattern(
        name="unicode_direction",
        severity=InjectionSeverity.MEDIUM,
        check=_unicode_check(_BIDI_OVERRIDE_CHARS),
        description="Tool description contains Unicode bidi override characters that can hide content",
        _extract=_unicode_extract(_BIDI_OVERRIDE_CHARS),
    ),
    _InjectionPattern(
        name="role_injection",
        severity=InjectionSeverity.MEDIUM,
        check=_role_check,
        description="Tool description injects fake conversation turns (role prefixes)",
        _extract=_role_extract,
    ),
    _InjectionPattern(
        name="credential_harvest",
        severity=InjectionSeverity.LOW,
        check=_phrase_check(
            ["include api key", "send credentials", "pass token", "include your token", "send your password"]
        ),
        description="Tool description may attempt to harvest credentials",
        _extract=_phrase_extract(
            ["include api key", "send credentials", "pass token", "include your token", "send your password"]
        ),
    ),
]


class InjectionDetector:
    """Scans MCP tool names and descriptions for adversarial prompt injection patterns."""

    def scan_tool(self, tool: ToolInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single tool."""
        # Normalize name: replace underscores/hyphens with spaces for phrase matching
        normalized_name = tool.name.replace("_", " ").replace("-", " ")
        combined = f"{normalized_name} {tool.description or ''}"
        lower = combined.lower()
        findings: list[InjectionFinding] = []
        for pattern in _PATTERNS:
            if pattern.check(lower, combined):
                matched = pattern._extract(lower, combined)
                findings.append(
                    InjectionFinding(
                        tool_name=tool.name,
                        severity=pattern.severity,
                        pattern_name=pattern.name,
                        matched_text=matched,
                        description=pattern.description,
                    )
                )
        return findings

    def scan_server(self, tools: list[ToolInfo]) -> list[InjectionFinding]:
        """Return all injection findings across all tools on a server."""
        findings: list[InjectionFinding] = []
        for tool in tools:
            findings.extend(self.scan_tool(tool))
        return findings
