"""Permission inference engine — keyword heuristics + MCP annotation analysis."""

from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding, ToolAnnotations, ToolInfo
from mcp_audit.rules.patterns import PERMISSION_PATTERNS

# Keyword strength → score contribution per match (multiplied by source weight later)
_STRENGTH_SCORES: dict[str, int] = {"strong": 3, "moderate": 2, "weak": 1}

# Weighted score thresholds for confidence levels
_HIGH_THRESHOLD = 6   # ≥2 strong name hits (3*weight=3 * 2 = 6)
_MEDIUM_THRESHOLD = 2
_LOW_THRESHOLD = 1


class PermissionAnalyzer:
    """Infers permission categories for MCP tools via annotations and keyword patterns."""

    def analyze_server(self, tools: list[ToolInfo]) -> list[PermissionFinding]:
        """Return all permission findings across all tools on a server."""
        findings: list[PermissionFinding] = []
        for tool in tools:
            findings.extend(self.analyze_tool(tool))
        return findings

    def analyze_tool(self, tool: ToolInfo) -> list[PermissionFinding]:
        """Return permission findings for a single tool."""
        annotation_findings = self._annotation_findings(tool)
        annotation_categories = {f.category for f in annotation_findings}

        # Determine which categories are suppressed by annotations
        suppressed = self._suppressed_categories(tool.annotations)

        keyword_findings = [
            f for f in self._keyword_findings(tool)
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
            findings.append(PermissionFinding(
                category=PermissionCategory.FILE_READ,
                confidence=Confidence.DECLARED,
                evidence=["readOnlyHint=true"],
                tool_name=tool.name,
            ))

        # destructiveHint: None treated as true
        if ann.destructive_hint is True or ann.destructive_hint is None:
            _d = ann.destructive_hint
            evidence = "destructiveHint=true" if _d is True else "destructiveHint=null (spec default: true)"
            findings.append(PermissionFinding(
                category=PermissionCategory.DESTRUCTIVE,
                confidence=Confidence.DECLARED,
                evidence=[evidence],
                tool_name=tool.name,
            ))

        # openWorldHint: None treated as true
        if ann.open_world_hint is True or ann.open_world_hint is None:
            _o = ann.open_world_hint
            evidence = "openWorldHint=true" if _o is True else "openWorldHint=null (spec default: true)"
            findings.append(PermissionFinding(
                category=PermissionCategory.NETWORK,
                confidence=Confidence.DECLARED,
                evidence=[evidence],
                tool_name=tool.name,
            ))

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

            findings.append(PermissionFinding(
                category=category,
                confidence=confidence,
                evidence=evidence_list,
                tool_name=tool.name,
            ))

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
                        if pattern in text.lower():
                            total_score += strength_score * source_weight
                            if pattern not in evidence:
                                evidence.append(pattern)

            results[category] = (total_score, evidence)

        return results
