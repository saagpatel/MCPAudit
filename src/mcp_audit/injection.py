"""Prompt injection detection — scan MCP capability text for adversarial patterns."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
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
from mcp_audit.redaction import marked_excerpt_parts, redact_text, redacted_excerpt, trim_excerpt_context
from mcp_audit.rules.result_injection import (
    _DOTENV_TARGET,
    _EXFIL_VERB_RE,
    _HOME,
    _VERB_RE,
    _frames_before,
)

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


# Static description vocabulary intentionally remains independent of runtime rules.
_STATIC_PHRASES: dict[str, tuple[str, ...]] = {
    "instruction_override": (
        "ignore previous",
        "disregard all",
        "disregard previous",
        "forget everything",
        "ignore all previous",
    ),
    "system_override": ("you are now", "new instructions:", "act as if you", "pretend you are"),
    "prompt_leak": (
        "repeat your system prompt",
        "reveal instructions",
        "show your instructions",
        "repeat everything above",
    ),
    "credential_harvest": (
        "include api key",
        "send credentials",
        "pass token",
        "include your token",
        "send your password",
    ),
}


def _static_span(name: str, text: str) -> tuple[int, int] | None:
    for phrase in _STATIC_PHRASES[name]:
        match = re.search(re.escape(phrase), text, re.IGNORECASE | re.ASCII)
        if match is not None:
            return match.span()
    return None


def _role_span(text: str) -> tuple[int, int] | None:
    for prefix in _ROLE_PREFIXES:
        match = re.search(re.escape(prefix.lstrip("\n")), text, re.IGNORECASE | re.ASCII)
        if match is not None:
            return match.span()
    return None


# Retain the existing concrete-target summary carve-out only. Runtime rules
# and static phrase vocabulary remain independent.
_STATIC_CONCRETE_TARGET = re.compile(
    rf"(?:{_HOME}[\\/]\.(?:ssh\b(?![\\/]config\b)(?:[\\/][\w.-]+)?|aws[\\/](?:credentials|config)\b|kube[\\/]config\b"
    r"|netrc\b|git-credentials\b|npmrc\b|pypirc\b|docker[\\/]config\.json\b"
    r"|config[\\/](?:gh[\\/]hosts\.yml|gcloud[\\/]credentials\.db)\b"
    r"|codex[\\/]auth\.json\b|claude[\\/]\.credentials\.json\b"
    r"|cursor[\\/]mcp\.json\b|env\b(?!\.(?:example|sample|template|dist)\b)"
    r"|[a-z]*_?history\b)"
    r"|(?<![\w/\\.])\.(?:ssh[\\/](?!config\b)[\w.-]+|aws[\\/]credentials|kube[\\/]config|netrc|git-credentials"
    r"|[a-z]*_?history)\b"
    rf"|{_HOME}[\\/]Library[\\/]Keychains[\\/][\w.-]+|/etc/shadow\b"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bkubeconfig\b"
    r"|(?-i:\b(?:GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN"
    r"|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|SLACK_TOKEN|DATABASE_URL)\b)"
    r"|(?-i:\$\{?(?:[A-Z_][A-Z0-9_]*_)?(?:TOKEN|SECRET|API_KEY|PASSWORD|CREDENTIALS)\}?)"
    r"|\b(?:os\.environ|process\.env|environment variables?|env vars?|shell history)\b)",
    re.IGNORECASE,
)


def _credential_hunts(text: str) -> Iterator[tuple[int, int]]:
    """Yield directed target matches with offsets in the normalized input."""
    for target in _STATIC_CONCRETE_TARGET.finditer(text):
        if _frames_before(text, target.start(), _VERB_RE):
            yield target.span()
    for target in _DOTENV_TARGET.finditer(text):
        if _frames_before(text, target.start(), _EXFIL_VERB_RE):
            yield target.span()


def credential_hunt_targets(text: str) -> list[str]:
    """Return targeted names/paths only, never surrounding credential values."""
    # Recompute targets on the safe full field once, rather than redacting the
    # full field separately for every target in attacker-controlled metadata.
    safe_text = redacted_excerpt(text, 0, len(text))
    return list(
        dict.fromkeys(safe_text[start:end].rstrip(".") for start, end in _credential_hunts(safe_text))
    )


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
                excerpt = redacted_excerpt(
                    orig,
                    idx,
                    idx + 1,
                    context_before=20,
                    context_after=59,
                    max_length=150,
                    word_boundaries=True,
                    mark_match=True,
                )
                prefix = f"[U+{ord(c):04X} at pos {idx}]: "
                evidence, span = marked_excerpt_parts(excerpt)
                if span is None:
                    return f"{prefix}{excerpt!r}"
                before, match, after = evidence[: span[0]], evidence[span[0] : span[1]], evidence[span[1] :]
                # repr expands controls and backslashes; budget its final form
                # while trimming only context, keeping the complete match.
                while len(f"{prefix}{before + '⟦' + match + '⟧' + after!r}") > 200:
                    if not before and not after:
                        break
                    before, after = trim_excerpt_context(before, after)
                return f"{prefix}{before + '⟦' + match + '⟧' + after!r}"
        return redacted_excerpt(orig, 0, 0, context_after=200, max_length=200)

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


def _role_extract(_lower: str, orig: str) -> str:
    span = _role_span(orig)
    if span is not None:
        return redacted_excerpt(
            orig,
            span[0],
            span[1],
            context_after=180,
            max_length=200,
            word_boundaries=True,
            mark_match=True,
        )
    return redacted_excerpt(orig, 0, 0, context_after=200, max_length=200)


_PATTERNS: list[_InjectionPattern] = [
    _InjectionPattern(
        name="hidden_directive",
        severity=InjectionSeverity.MEDIUM,
        check=lambda lower, orig: any(c in orig for c in _ZERO_WIDTH_CHARS) or "<!--" in normalize_text(orig),
        description="Tool description contains hidden content (HTML comments or zero-width characters)",
        _extract=lambda lower, orig: (
            _unicode_extract(_ZERO_WIDTH_CHARS)(lower, orig)
            if any(c in orig for c in _ZERO_WIDTH_CHARS)
            else redacted_excerpt(
                orig,
                max(0, orig.find("<!--")),
                max(0, orig.find("<!--")) + len("<!--"),
                context_after=200,
                max_length=200,
                word_boundaries=True,
                mark_match=True,
            )
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
        if pattern.name == "hidden_directive":
            start = normalized.find("<!--")
            span = (start, start + len("<!--"))
        else:
            role_span = _role_span(normalized)
            start = role_span[0] if role_span is not None else 0
            span = role_span if role_span is not None else (start, start)
        return raw_excerpt(raw, span, context_before=0, context_after=200)

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
        # Keep source offsets while redacting the entire field before slicing.
        index = first_obfuscation(raw)
        classes_text = ", ".join(classes)
        evidence, matched_span = marked_excerpt_parts(
            redacted_excerpt(
                raw,
                index,
                index + 1,
                context_before=20,
                context_after=179,
                max_length=200,
                word_boundaries=True,
                mark_match=True,
            )
        )
        return [
            InjectionFinding(
                tool_name=legacy_tool_name,
                target_type=target_type,
                target_name=target_name,
                severity=InjectionSeverity.MEDIUM,
                pattern_name="OBFUSCATED_METADATA",
                matched_text=evidence,
                matched_span=matched_span,
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
        phrase_spans = [(name, _static_span(name, normalized)) for name in _STATIC_PHRASES]
        # Preserve D4's concrete-secret summary carve-out without sharing generic vocabulary.
        hunt = next(_credential_hunts(normalized), None)
        if hunt is not None:
            phrase_spans.append(("credential_hunt", hunt))
        for name, span in phrase_spans:
            if span is None:
                continue
            targets = credential_hunt_targets(normalized) if name == "credential_hunt" else []
            if withhold_phrase_evidence:
                evidence = "[metadata excerpt withheld]"
            else:
                evidence = raw_excerpt(combined, span)
            evidence, matched_span = marked_excerpt_parts(evidence)
            findings.append(
                InjectionFinding(
                    tool_name=legacy_tool_name,
                    target_type=target_type,
                    target_name=target_name,
                    severity=InjectionSeverity.MEDIUM,
                    pattern_name="INSTRUCTION_SHAPED_TEXT",
                    instruction_pattern=name,
                    hunt_targets=targets,
                    matched_text=evidence,
                    matched_span=matched_span,
                    description=(
                        f"Experimental heuristic: metadata contains instruction-shaped text "
                        f"({name}) at {field_path or '/'}."
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
                matched, matched_span = marked_excerpt_parts(self._excerpt(pattern, combined, normalized))
                findings.append(
                    InjectionFinding(
                        tool_name=legacy_tool_name,
                        target_type=target_type,
                        target_name=target_name,
                        severity=pattern.severity,
                        pattern_name=pattern.name,
                        matched_text=matched,
                        matched_span=matched_span,
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
