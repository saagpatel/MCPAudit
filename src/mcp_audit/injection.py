"""Prompt injection detection — scan MCP capability text for adversarial patterns."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from mcp_audit.agent_text import AgentText, agent_visible_text, prompt_visible_text
from mcp_audit.models import (
    CapabilityTarget,
    InjectionFinding,
    InjectionSeverity,
    PromptInfo,
    ResourceInfo,
    ToolInfo,
)
from mcp_audit.normalize import first_obfuscation, normalize_text, obfuscation_classes, raw_excerpt
from mcp_audit.redaction import redact_text
from mcp_audit.rules.result_injection import INSTRUCTION_TEXT_RULES, credential_hunt_targets

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
    # Each metadata field is scanned separately; role turns begin a line.
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
        name="hidden_directive",
        severity=InjectionSeverity.MEDIUM,
        check=lambda lower, orig: (
            any(c in orig for c in _ZERO_WIDTH_CHARS)
            or ("<!--" in lower and any(rule.check(normalize_text(orig)) for rule in INSTRUCTION_TEXT_RULES))
        ),
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
        return self._scan_fields(CapabilityTarget.TOOL, tool.name, agent_visible_text(tool))

    def scan_prompt(self, prompt: PromptInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single prompt."""
        return self._scan_fields(CapabilityTarget.PROMPT, prompt.name, prompt_visible_text(prompt))

    def scan_resource(self, resource: ResourceInfo) -> list[InjectionFinding]:
        """Return all injection findings for a single resource."""
        findings: list[InjectionFinding] = []
        for path, text in (
            ("/uri", resource.uri),
            ("/name", resource.name or ""),
            ("/description", resource.description or ""),
            ("/mime_type", resource.mime_type or ""),
        ):
            if text:
                findings.extend(
                    self._scan_text(CapabilityTarget.RESOURCE, resource.uri, text, resource.uri, path)
                )
        return findings

    def _scan_fields(
        self, target_type: CapabilityTarget, target_name: str, fields: AgentText
    ) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []
        for field in fields.fields:
            normalized = normalize_text(field.text)
            if field.path == "/name":
                normalized = normalized.replace("_", " ").replace("-", " ")
            findings.extend(
                self._scan_text(
                    target_type, target_name, field.text, target_name, field.path, normalized=normalized
                )
            )
        return findings

    @staticmethod
    def _matches(pattern: _InjectionPattern, raw: str, normalized: str) -> bool:
        original = raw if pattern.name in {"hidden_directive", "unicode_direction"} else normalized
        return pattern.check(normalized.lower(), original)

    @staticmethod
    def _excerpt(pattern: _InjectionPattern, raw: str, normalized: str) -> str:
        if (
            normalized == raw
            or pattern.name == "unicode_direction"
            or (pattern.name == "hidden_directive" and any(c in raw for c in _ZERO_WIDTH_CHARS))
        ):
            return pattern._extract(raw.lower(), raw)
        excerpt = pattern._extract(normalized.lower(), normalized)
        if pattern.name == "hidden_directive":
            start = normalized.find("<!--")
            span = (start, start + len("<!--"))
        else:
            start = normalized.find(excerpt)
            span = (max(0, start), max(0, start) + len(excerpt))
        return raw_excerpt(raw, normalized, excerpt, span)

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
        normalized: str | None = None,
    ) -> list[InjectionFinding]:
        """Return all injection findings for one normalized capability text blob."""
        if normalized is None:
            normalized = normalize_text(combined)
        # Redact complete fields before excerpt boundaries can discard a credential label.
        withhold_phrase_evidence = redact_text(combined) != combined or redact_text(normalized) != normalized
        findings: list[InjectionFinding] = []
        for rule in INSTRUCTION_TEXT_RULES:
            span = rule.span(normalized)
            if span is None:
                continue
            targets = (
                credential_hunt_targets(normalized, concrete_only=True)
                if rule.name == "credential_hunt"
                else []
            )
            if withhold_phrase_evidence:
                evidence = "[metadata excerpt withheld]"
            else:
                excerpt = normalized[max(0, span[0] - 20) : span[1] + 80]
                evidence = raw_excerpt(combined, normalized, excerpt, span)
            findings.append(
                InjectionFinding(
                    tool_name=legacy_tool_name,
                    target_type=target_type,
                    target_name=target_name,
                    severity=InjectionSeverity.MEDIUM,
                    pattern_name="INSTRUCTION_SHAPED_TEXT",
                    instruction_pattern=rule.name,
                    secret_targets=targets,
                    matched_text=evidence[:200],
                    description=(
                        f"Experimental heuristic: metadata contains instruction-shaped text "
                        f"({rule.name}) at {field_path or '/'}."
                        + (f" Secret targets: {', '.join(targets)}." if targets else "")
                    ),
                    field_path=field_path,
                )
            )
        for blob in re.finditer(r"[A-Za-z0-9+/_=-]{80,}", normalized):
            counts = Counter(blob.group())
            length = len(blob.group())
            entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
            if entropy >= 4.5:
                findings.append(
                    InjectionFinding(
                        tool_name=legacy_tool_name,
                        target_type=target_type,
                        target_name=target_name,
                        severity=InjectionSeverity.LOW,
                        pattern_name="ENCODED_BLOB_IN_METADATA",
                        matched_text=f"[{length}-character high-entropy run; content withheld]",
                        description="Structural heuristic: high-entropy run; never decoded or executed.",
                        field_path=field_path,
                    )
                )
                break
        for pattern in _PATTERNS:
            if self._matches(pattern, combined, normalized):
                matched = redact_text(self._excerpt(pattern, combined, normalized))[:200]
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
