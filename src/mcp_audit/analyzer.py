"""Permission inference engine — keyword heuristics + MCP annotation analysis."""

import re
from functools import cache
from urllib.parse import urlparse

from mcp_audit.models import (
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    PromptInfo,
    ResourceInfo,
    ToolAnnotations,
    ToolInfo,
)
from mcp_audit.rules.patterns import PERMISSION_PATTERNS

# Keyword strength → score contribution per match (multiplied by source weight later)
_STRENGTH_SCORES: dict[str, int] = {"strong": 3, "moderate": 2, "weak": 1}


@cache
def _pattern_regex(pattern: str) -> re.Pattern[str]:
    """Letter-boundary matcher for a capability keyword. Patterns are identifier
    tokens ('rm', 'port', 'read_file'), so they must match whole tokens, not
    substrings inside ordinary words ('terms', 'portfolio', 'evaluation'). The
    boundary is letters-only, so identifier separators (_, -, /, .) still delimit
    tokens: 'url' matches 'download_url' but not 'curl', 'port' never matches
    'portfolio'."""
    return re.compile(rf"(?<![a-z]){re.escape(pattern)}(?![a-z])")


# Weighted score thresholds for confidence levels
_HIGH_THRESHOLD = 6  # ≥2 strong name hits (3*weight=3 * 2 = 6)
_MEDIUM_THRESHOLD = 2
_LOW_THRESHOLD = 1

_REMOTE_RESOURCE_SCHEMES = {
    "az",
    "azure",
    "git",
    "github",
    "gs",
    "http",
    "https",
    "mongodb",
    "mysql",
    "postgres",
    "postgresql",
    "redis",
    "s3",
    "ws",
    "wss",
}


class PermissionAnalyzer:
    """Infers permission categories for MCP tools via annotations and keyword patterns."""

    def analyze_server(self, tools: list[ToolInfo]) -> list[PermissionFinding]:
        """Return all permission findings across all tools on a server."""
        findings: list[PermissionFinding] = []
        for tool in tools:
            findings.extend(self.analyze_tool(tool))
        return findings

    def analyze_capabilities(
        self, prompts: list[PromptInfo], resources: list[ResourceInfo]
    ) -> list[CapabilityFinding]:
        """Return permission findings for non-tool MCP capabilities."""
        findings: list[CapabilityFinding] = []
        for prompt in prompts:
            findings.extend(self.analyze_prompt(prompt))
        for resource in resources:
            findings.extend(self.analyze_resource(resource))
        return findings

    def analyze_prompt(self, prompt: PromptInfo) -> list[CapabilityFinding]:
        sources: list[tuple[str, int]] = [
            (prompt.name, 3),
            (prompt.description or "", 2),
            *[(argument, 1) for argument in prompt.arguments],
        ]
        return self._capability_findings(CapabilityTarget.PROMPT, prompt.name, sources)

    def analyze_resource(self, resource: ResourceInfo) -> list[CapabilityFinding]:
        parsed = urlparse(resource.uri)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        path = parsed.path or ""
        sources: list[tuple[str, int]] = [
            (resource.uri, 3),
            (scheme, 2),
            (host, 2),
            (path, 2),
            (resource.name or "", 2),
            (resource.description or "", 2),
            (resource.mime_type or "", 1),
        ]
        findings = self._capability_findings(CapabilityTarget.RESOURCE, resource.uri, sources)

        if scheme == "file" and not any(f.category == PermissionCategory.FILE_READ for f in findings):
            findings.append(
                CapabilityFinding(
                    target_type=CapabilityTarget.RESOURCE,
                    target_name=resource.uri,
                    category=PermissionCategory.FILE_READ,
                    confidence=Confidence.HIGH,
                    evidence=["resource URI scheme 'file'"],
                )
            )
        if scheme in _REMOTE_RESOURCE_SCHEMES:
            evidence = [f"resource URI scheme '{scheme}'"]
            if host:
                evidence.append(f"resource host '{host}'")
            existing_network = next(
                (finding for finding in findings if finding.category == PermissionCategory.NETWORK),
                None,
            )
            if existing_network is None:
                findings.append(
                    CapabilityFinding(
                        target_type=CapabilityTarget.RESOURCE,
                        target_name=resource.uri,
                        category=PermissionCategory.NETWORK,
                        confidence=Confidence.HIGH,
                        evidence=evidence,
                    )
                )
            else:
                existing_network.evidence = [*existing_network.evidence, *evidence]
                existing_network.confidence = Confidence.HIGH
        if (
            "{" in resource.uri
            and "}" in resource.uri
            and not any(f.category == PermissionCategory.NETWORK for f in findings)
        ):
            findings.append(
                CapabilityFinding(
                    target_type=CapabilityTarget.RESOURCE,
                    target_name=resource.uri,
                    category=PermissionCategory.NETWORK,
                    confidence=Confidence.MEDIUM,
                    evidence=["resource URI contains template variables"],
                )
            )
        return findings

    def analyze_tool(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Return permission findings for a single tool."""
        annotation_findings = self._annotation_findings(tool)
        annotation_categories = {f.category for f in annotation_findings}

        # Determine which categories are suppressed by annotations
        suppressed = self._suppressed_categories(tool.annotations)

        keyword_findings = [
            f
            for f in self._keyword_findings(tool)
            if f.category not in annotation_categories and f.category not in suppressed
        ]

        return annotation_findings + keyword_findings

    def _annotation_findings(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Produce DECLARED findings from MCP tool annotations and spec defaults."""
        if tool.annotations is None:
            # MCP spec defaults: destructiveHint=true, openWorldHint=true
            return [
                PermissionFinding(
                    category=PermissionCategory.DESTRUCTIVE,
                    confidence=Confidence.DECLARED,
                    evidence=["destructiveHint=null (spec default: true)"],
                    tool_name=tool.name,
                ),
                PermissionFinding(
                    category=PermissionCategory.NETWORK,
                    confidence=Confidence.DECLARED,
                    evidence=["openWorldHint=null (spec default: true)"],
                    tool_name=tool.name,
                ),
            ]

        ann = tool.annotations
        findings: list[PermissionFinding] = []

        # readOnlyHint: None treated as false (no FILE_READ from annotation alone)
        if ann.read_only_hint is True:
            findings.append(
                PermissionFinding(
                    category=PermissionCategory.FILE_READ,
                    confidence=Confidence.DECLARED,
                    evidence=["readOnlyHint=true"],
                    tool_name=tool.name,
                )
            )

        # destructiveHint: None treated as true
        if ann.destructive_hint is True or ann.destructive_hint is None:
            _d = ann.destructive_hint
            evidence = "destructiveHint=true" if _d is True else "destructiveHint=null (spec default: true)"
            findings.append(
                PermissionFinding(
                    category=PermissionCategory.DESTRUCTIVE,
                    confidence=Confidence.DECLARED,
                    evidence=[evidence],
                    tool_name=tool.name,
                )
            )

        # openWorldHint: None treated as true
        if ann.open_world_hint is True or ann.open_world_hint is None:
            _o = ann.open_world_hint
            evidence = "openWorldHint=true" if _o is True else "openWorldHint=null (spec default: true)"
            findings.append(
                PermissionFinding(
                    category=PermissionCategory.NETWORK,
                    confidence=Confidence.DECLARED,
                    evidence=[evidence],
                    tool_name=tool.name,
                )
            )

        return findings

    def _suppressed_categories(self, ann: ToolAnnotations | None) -> set[PermissionCategory]:
        """Return categories that should be suppressed by annotation hints."""
        if ann is None:
            return set()
        suppressed: set[PermissionCategory] = set()
        if ann.read_only_hint is True:
            suppressed.add(PermissionCategory.FILE_WRITE)
            suppressed.add(PermissionCategory.DESTRUCTIVE)
        if ann.destructive_hint is False:
            suppressed.add(PermissionCategory.DESTRUCTIVE)
        if ann.open_world_hint is False:
            suppressed.add(PermissionCategory.NETWORK)
            suppressed.add(PermissionCategory.EXFILTRATION)
        return suppressed

    def _keyword_findings(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Score keyword patterns across tool name, description, and param names."""
        # Build text sources: (text, weight)
        sources: list[tuple[str, int]] = [
            (tool.name, 3),
            (tool.description or "", 2),
        ]
        if tool.input_schema:
            props = tool.input_schema.get("properties", {})
            if isinstance(props, dict):
                for param_name in props:
                    sources.append((str(param_name), 1))

        scores = self._score_keywords(sources)
        findings: list[PermissionFinding] = []

        for category, (weighted_score, evidence_list) in scores.items():
            if weighted_score < _LOW_THRESHOLD:
                continue
            if weighted_score >= _HIGH_THRESHOLD:
                confidence = Confidence.HIGH
            elif weighted_score >= _MEDIUM_THRESHOLD:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW

            findings.append(
                PermissionFinding(
                    category=category,
                    confidence=confidence,
                    evidence=evidence_list,
                    tool_name=tool.name,
                )
            )

        return findings

    def _score_keywords(
        self, sources: list[tuple[str, int]]
    ) -> dict[PermissionCategory, tuple[int, list[str]]]:
        """Return (weighted_score, evidence) per category."""
        results: dict[PermissionCategory, tuple[int, list[str]]] = {}

        for category, strengths in PERMISSION_PATTERNS.items():
            total_score = 0
            evidence: list[str] = []

            for strength, patterns in strengths.items():
                strength_score = _STRENGTH_SCORES[strength]
                for pattern in patterns:
                    for text, source_weight in sources:
                        if _pattern_regex(pattern).search(text.lower()):
                            total_score += strength_score * source_weight
                            if pattern not in evidence:
                                evidence.append(pattern)

            results[category] = (total_score, evidence)

        return results

    def _capability_findings(
        self,
        target_type: CapabilityTarget,
        target_name: str,
        sources: list[tuple[str, int]],
    ) -> list[CapabilityFinding]:
        scores = self._score_keywords(sources)
        findings: list[CapabilityFinding] = []

        for category, (weighted_score, evidence_list) in scores.items():
            if weighted_score < _LOW_THRESHOLD:
                continue
            if weighted_score >= _HIGH_THRESHOLD:
                confidence = Confidence.HIGH
            elif weighted_score >= _MEDIUM_THRESHOLD:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW

            findings.append(
                CapabilityFinding(
                    target_type=target_type,
                    target_name=target_name,
                    category=category,
                    confidence=confidence,
                    evidence=evidence_list,
                )
            )

        return findings
