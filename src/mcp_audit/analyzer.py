"""Permission inference engine — keyword heuristics + MCP annotation analysis."""

import re
from functools import cache
from urllib.parse import urlparse

from mcp_audit.agent_text import agent_visible_text
from mcp_audit.models import (
    AnnotationFinding,
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    PromptInfo,
    ResourceInfo,
    ToolInfo,
)
from mcp_audit.rules.patterns import PERMISSION_PATTERNS
from mcp_audit.text_limits import bounded_text

# Keyword strength → score contribution per match (multiplied by source weight later)
_STRENGTH_SCORES: dict[str, int] = {"strong": 3, "moderate": 2, "weak": 1}
_CAMEL_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_WORD_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _keyword_text(text: str) -> str:
    """Normalize identifier text before keyword matching.

    MCP servers commonly use both snake_case and camelCase names; normalize
    camelCase to separator-delimited tokens before lowercasing so `readFile`
    still matches the `read_file` keyword while `report` still does not match
    the `port` keyword.
    """
    text = _CAMEL_ACRONYM_BOUNDARY.sub("_", text)
    return _CAMEL_WORD_BOUNDARY.sub("_", text).lower()


@cache
def _pattern_regex(pattern: str) -> re.Pattern[str]:
    """Letter-boundary matcher for a capability keyword. Patterns are identifier
    tokens ('rm', 'port', 'read_file'), so they must match whole tokens, not
    substrings inside ordinary words ('terms', 'portfolio', 'evaluation'). The
    boundary is letters-only, so identifier separators (_, -, /, .) still delimit
    tokens: 'url' matches 'download_url' but not 'curl', 'port' never matches
    'portfolio'."""
    return re.compile(rf"(?<![a-z]){re.escape(pattern)}(?![a-z])")


@cache
def _category_regex(
    category: PermissionCategory,
) -> tuple[re.Pattern[str], dict[str, set[str]]]:
    patterns = [pattern for group in PERMISSION_PATTERNS[category].values() for pattern in group]
    alternatives = "|".join(re.escape(pattern) for pattern in sorted(set(patterns), key=len, reverse=True))
    # Lookahead retains overlaps such as working_directory / directory. Expand
    # longest matches to retain same-start hits such as read_file / read too.
    regex = re.compile(rf"(?=(?<![a-z])({alternatives})(?![a-z]))")
    contained = {
        match: {pattern for pattern in patterns if _pattern_regex(pattern).search(match)}
        for match in patterns
    }
    return regex, contained


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

        keyword_findings = [
            f for f in self._keyword_findings(tool) if f.category not in annotation_categories
        ]

        return annotation_findings + keyword_findings

    def analyze_tool_keywords(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Infer capabilities without allowing server annotations to suppress hints."""
        return self._keyword_findings(tool)

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

        # destructiveHint: None treated as true, but per the MCP spec it is
        # meaningful only when readOnlyHint is false.
        if ann.read_only_hint is not True and (ann.destructive_hint is True or ann.destructive_hint is None):
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

    def analyze_annotation_contradictions(self, tool: ToolInfo) -> list[AnnotationFinding]:
        """Compare explicit served hints with existing keyword capability evidence."""
        ann = tool.annotations
        if ann is None:
            return []
        contradictions: list[AnnotationFinding] = []
        for finding in self.analyze_tool_keywords(tool):
            if finding.confidence not in {Confidence.MEDIUM, Confidence.HIGH}:
                continue
            hint: str | None = None
            declared_value = False
            if ann.read_only_hint is True and finding.category in {
                PermissionCategory.FILE_WRITE,
                PermissionCategory.DESTRUCTIVE,
            }:
                hint, declared_value = "readOnlyHint", True
            elif (
                ann.read_only_hint is not True
                and ann.destructive_hint is False
                and finding.category == PermissionCategory.DESTRUCTIVE
            ):
                hint = "destructiveHint"
            elif ann.open_world_hint is False and finding.category in {
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            }:
                hint = "openWorldHint"
            if hint is not None:
                contradictions.append(
                    AnnotationFinding(
                        tool_name=tool.name,
                        hint=hint,
                        declared_value=declared_value,
                        category=finding.category,
                        confidence=finding.confidence,
                        severity="high" if finding.category == PermissionCategory.DESTRUCTIVE else "medium",
                        evidence=finding.evidence,
                        field_paths=finding.field_paths,
                    )
                )
        return contradictions

    def _keyword_findings(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Score bounded agent-visible text; added metadata has weight one."""
        fields = agent_visible_text(tool).fields
        weights = {"/name": 3, "/description": 2}
        sources = [(field.text, weights.get(field.path, 1)) for field in fields]
        scores = self._score_keywords(sources, [field.path for field in fields])
        findings: list[PermissionFinding] = []

        for category, (weighted_score, evidence_list, field_paths) in scores.items():
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
                    field_paths=field_paths,
                )
            )

        return findings

    def _score_keywords(
        self, sources: list[tuple[str, int]], paths: list[str] | None = None
    ) -> dict[PermissionCategory, tuple[int, list[str], list[str]]]:
        """Return (weighted_score, evidence, field_paths) per category."""
        results: dict[PermissionCategory, tuple[int, list[str], list[str]]] = {}
        normalized = [(_keyword_text(bounded_text(text)), weight) for text, weight in sources]

        for category, strengths in PERMISSION_PATTERNS.items():
            total_score = 0
            evidence: list[str] = []
            regex, contained = _category_regex(category)
            source_hits: list[tuple[set[str], int]] = []
            for text, weight in normalized:
                hits: set[str] = set()
                for match in regex.finditer(text):
                    hits.update(contained[match.group(1)])
                source_hits.append((hits, weight))
            matched_paths: list[str] = []

            for strength, patterns in strengths.items():
                strength_score = _STRENGTH_SCORES[strength]
                for pattern in patterns:
                    for index, (hits, source_weight) in enumerate(source_hits):
                        if pattern in hits:
                            total_score += strength_score * source_weight
                            if pattern not in evidence:
                                evidence.append(pattern)
                            if paths is not None and paths[index] not in matched_paths:
                                matched_paths.append(paths[index])

            results[category] = (total_score, evidence, matched_paths)

        return results

    def _capability_findings(
        self,
        target_type: CapabilityTarget,
        target_name: str,
        sources: list[tuple[str, int]],
    ) -> list[CapabilityFinding]:
        scores = self._score_keywords(sources)
        findings: list[CapabilityFinding] = []

        for category, (weighted_score, evidence_list, _) in scores.items():
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
