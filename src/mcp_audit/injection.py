"""Prompt injection detection — scan MCP capability text for adversarial patterns."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mcp_audit.agent_text import agent_visible_text, prompt_visible_text
from mcp_audit.models import (
    CapabilityTarget,
    InjectionFinding,
    InjectionSeverity,
    PromptInfo,
    ResourceInfo,
    ToolInfo,
)
from mcp_audit.normalize import first_obfuscation, normalize_text, obfuscation_classes, raw_excerpt

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
    # Match at start of text or after any newline; scan_* joins the name and
    # description segments with newlines, so segment starts are line starts.
    for prefix in _ROLE_PREFIXES:
        clean = prefix.lstrip("\n")
        if lower.startswith(clean):
            return True
        if f"\n{clean}" in lower:
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
    """Scans agent-visible MCP capability text for prompt injection patterns."""

    def scan_result(
        self,
        tool_name: str,
        text: str,
        after_call: int,
        target_type: CapabilityTarget = CapabilityTarget.TOOL,
    ) -> list[InjectionFinding]:
        """Scan untrusted runtime text without echoing possible credential values.

        ``target_type`` is TOOL for tools/call results and PROMPT for rendered
        prompts/get bodies; both are scanned with the same rules. The caller
        bounds ``text`` (see ``RESULT_SCAN_LIMIT``).
        """
        from mcp_audit.rules.result_injection import RESULT_INJECTION_RULES

        prompt_body = target_type is CapabilityTarget.PROMPT
        source = "prompts/get body" if prompt_body else "Tool result"
        withheld = "[prompt-body excerpt withheld]" if prompt_body else "[tool-result excerpt withheld]"
        normalized = normalize_text(text)
        findings = [
            InjectionFinding(
                tool_name=tool_name,
                target_type=target_type,
                target_name=tool_name,
                # Free-text heuristics are experimental: they inform at MEDIUM and never
                # reach a HIGH gate on their own. Session drift carries the canary's verdict.
                severity=InjectionSeverity.MEDIUM,
                pattern_name=name,
                after_call=after_call,
                matched_text=withheld,
                description=(
                    f"Experimental heuristic: {source} after canary call {after_call} "
                    "contains instruction-shaped text."
                ),
            )
            for name, rule in RESULT_INJECTION_RULES.items()
            if rule(normalized)
        ]
        classes = obfuscation_classes(text)
        if classes:
            findings.append(
                InjectionFinding(
                    tool_name=tool_name,
                    target_type=target_type,
                    target_name=tool_name,
                    severity=InjectionSeverity.MEDIUM,
                    pattern_name="OBFUSCATED_METADATA",
                    after_call=after_call,
                    matched_text=withheld,
                    description=f"{source} contains {', '.join(classes)} codepoints at /body.",
                )
            )
        return findings

    def scan_tool(self, tool: ToolInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single tool."""
        fields = agent_visible_text(tool).fields
        name = fields[0].text.replace("_", " ").replace("-", " ")
        description = fields[1].text
        normalized_name = normalize_text(fields[0].text).replace("_", " ").replace("-", " ")
        normalized_description = normalize_text(description)
        unicode_changed = (
            normalize_text(fields[0].text) != fields[0].text or normalized_description != description
        )
        evidence_name = fields[0].text if unicode_changed else name
        # Retain legacy name/description excerpts and Unicode offsets. Additional
        # fields are scanned separately so their evidence has a precise pointer.
        findings = self._scan_text(
            CapabilityTarget.TOOL,
            tool.name,
            f"{evidence_name}\n{description}",
            tool.name,
            structural=False,
            normalized=f"{normalized_name}\n{normalized_description}",
        )
        for finding in findings:
            pattern = next(p for p in _PATTERNS if p.name == finding.pattern_name)
            name_matches = self._matches(pattern, name, normalized_name)
            description_matches = self._matches(pattern, description, normalized_description)
            finding.field_path = "/name" if name_matches else "/description"
            # Phrase/character priority can pick a different source in a combined
            # excerpt. Resolve ambiguous matches locally; role extractors can
            # also select a non-anchored substring in the other field.
            if (name_matches and description_matches) or pattern.name == "role_injection":
                source = evidence_name if name_matches else description
                matching_text = normalized_name if name_matches else normalized_description
                finding.matched_text = self._excerpt(pattern, source, matching_text)
        for field in fields[:2]:
            findings.extend(
                self._obfuscation_findings(
                    CapabilityTarget.TOOL, tool.name, field.text, tool.name, field.path
                )
            )
        for field in fields[2:]:
            text = field.text
            findings.extend(self._scan_text(CapabilityTarget.TOOL, tool.name, text, tool.name, field.path))
        return findings

    def scan_prompt(self, prompt: PromptInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single prompt."""
        findings: list[InjectionFinding] = []
        for field in prompt_visible_text(prompt).fields:
            text = field.text.replace("_", " ").replace("-", " ") if field.path == "/name" else field.text
            normalized = normalize_text(field.text)
            if field.path == "/name":
                if normalized != field.text:
                    text = field.text
                normalized = normalized.replace("_", " ").replace("-", " ")
            findings.extend(
                self._scan_text(
                    CapabilityTarget.PROMPT, prompt.name, text, prompt.name, field.path, normalized=normalized
                )
            )
        return findings

    def scan_resource(self, resource: ResourceInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single resource."""
        fields = [
            ("/uri", resource.uri),
            ("/name", resource.name or ""),
            ("/description", resource.description or ""),
            ("/mime_type", resource.mime_type or ""),
        ]
        combined = "\n".join(text for _, text in fields if text)
        findings = self._scan_text(
            CapabilityTarget.RESOURCE, resource.uri, combined, resource.uri, structural=False
        )
        for path, text in fields:
            findings.extend(
                self._obfuscation_findings(CapabilityTarget.RESOURCE, resource.uri, text, resource.uri, path)
            )
        return findings

    @staticmethod
    def _matches(pattern: _InjectionPattern, raw: str, normalized: str) -> bool:
        original = raw if pattern.name in {"hidden_directive", "unicode_direction"} else normalized
        return pattern.check(normalized.lower(), original)

    @staticmethod
    def _excerpt(pattern: _InjectionPattern, raw: str, normalized: str) -> str:
        if normalized == raw or pattern.name in {"hidden_directive", "unicode_direction"}:
            return pattern._extract(raw.lower(), raw)
        excerpt = pattern._extract(normalized.lower(), normalized)
        return raw_excerpt(raw, normalized, excerpt)

    @staticmethod
    def _obfuscation_findings(
        target_type: CapabilityTarget,
        target_name: str,
        raw: str,
        legacy_tool_name: str,
        field_path: str | None,
    ) -> list[InjectionFinding]:
        classes = obfuscation_classes(raw)
        if not classes:
            return []
        # Preserve raw source evidence; reports make invisible codepoints visible.
        index = first_obfuscation(raw)
        classes_text = ", ".join(classes)
        return [
            InjectionFinding(
                tool_name=legacy_tool_name,
                target_type=target_type,
                target_name=target_name,
                severity=InjectionSeverity.MEDIUM,
                pattern_name="OBFUSCATED_METADATA",
                matched_text=raw[max(0, index - 20) : max(0, index - 20) + 200],
                description=(f"Agent-facing text contains {classes_text} codepoints at {field_path or '/'}."),
                field_path=field_path,
            )
        ]

    def _scan_text(
        self,
        target_type: CapabilityTarget,
        target_name: str,
        combined: str,
        legacy_tool_name: str,
        field_path: str | None = None,
        *,
        structural: bool = True,
        normalized: str | None = None,
    ) -> list[InjectionFinding]:
        """Return all injection findings for one normalized capability text blob."""
        if normalized is None:
            normalized = normalize_text(combined)
        findings: list[InjectionFinding] = []
        for pattern in _PATTERNS:
            if self._matches(pattern, combined, normalized):
                matched = self._excerpt(pattern, combined, normalized)
                findings.append(
                    InjectionFinding(
                        tool_name=legacy_tool_name,
                        target_type=target_type,
                        target_name=target_name,
                        severity=pattern.severity,
                        pattern_name=pattern.name,
                        matched_text=matched,
                        description=pattern.description,
                        field_path=field_path,
                    )
                )
        if structural:
            findings.extend(
                self._obfuscation_findings(target_type, target_name, combined, legacy_tool_name, field_path)
            )
        return findings

    def scan_server(
        self,
        tools: list[ToolInfo],
        prompts: list[PromptInfo] | None = None,
        resources: list[ResourceInfo] | None = None,
    ) -> list[InjectionFinding]:
        """Return all injection findings across all server capabilities."""
        findings: list[InjectionFinding] = []
        for tool in tools:
            findings.extend(self.scan_tool(tool))
        for prompt in prompts or []:
            findings.extend(self.scan_prompt(prompt))
        for resource in resources or []:
            findings.extend(self.scan_resource(resource))
        return findings
