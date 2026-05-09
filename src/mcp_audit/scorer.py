"""Risk scoring — weighted multi-dimensional scores per server."""

from collections.abc import Iterable

from mcp_audit.models import (
    CapabilityFinding,
    CapabilityTarget,
    InjectionFinding,
    InjectionSeverity,
    NonToolRisk,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
)
from mcp_audit.rules.weights import CATEGORY_WEIGHTS, CONFIDENCE_MULTIPLIERS

_INJECTION_SCORES: dict[InjectionSeverity, float] = {
    InjectionSeverity.HIGH: 7.0,
    InjectionSeverity.MEDIUM: 4.0,
    InjectionSeverity.LOW: 1.0,
}


class RiskScorer:
    """Computes multi-dimensional risk scores from a list of permission findings."""

    def score_server(self, permissions: list[PermissionFinding]) -> RiskScore:
        """Compute a RiskScore from all PermissionFindings for a server."""
        # FILE_READ and FILE_WRITE both contribute to file_access (take max)
        file_read = self._dim_score(permissions, PermissionCategory.FILE_READ)
        file_write = self._dim_score(permissions, PermissionCategory.FILE_WRITE)
        file_access = min(10.0, max(file_read, file_write))

        network_access = min(10.0, self._dim_score(permissions, PermissionCategory.NETWORK))
        shell_execution = min(10.0, self._dim_score(permissions, PermissionCategory.SHELL_EXEC))
        destructive = min(10.0, self._dim_score(permissions, PermissionCategory.DESTRUCTIVE))
        exfiltration = min(10.0, self._dim_score(permissions, PermissionCategory.EXFILTRATION))

        composite = min(10.0, file_access + network_access + shell_execution + destructive + exfiltration)

        return RiskScore(
            composite=composite,
            file_access=file_access,
            network_access=network_access,
            shell_execution=shell_execution,
            destructive=destructive,
            exfiltration=exfiltration,
        )

    def _dim_score(self, findings: list[PermissionFinding], category: PermissionCategory) -> float:
        """Return the highest-weighted score for a single permission category."""
        return self._category_score(findings, category)

    def score_non_tool(
        self,
        capability_findings: list[CapabilityFinding],
        injection_findings: list[InjectionFinding],
    ) -> NonToolRisk | None:
        """Compute additive prompt/resource risk without changing tool composite risk."""
        non_tool_injections = [
            finding
            for finding in injection_findings
            if finding.target_type in {CapabilityTarget.PROMPT, CapabilityTarget.RESOURCE}
        ]
        if not capability_findings and not non_tool_injections:
            return None

        capability_score = min(
            10.0,
            sum(self._category_score(capability_findings, category) for category in PermissionCategory),
        )
        injection_score = min(
            10.0,
            max((_INJECTION_SCORES[finding.severity] for finding in non_tool_injections), default=0.0),
        )
        composite = min(10.0, capability_score + injection_score)

        prompt_findings = sum(
            1 for finding in capability_findings if finding.target_type == CapabilityTarget.PROMPT
        ) + sum(1 for finding in non_tool_injections if finding.target_type == CapabilityTarget.PROMPT)
        resource_findings = sum(
            1 for finding in capability_findings if finding.target_type == CapabilityTarget.RESOURCE
        ) + sum(1 for finding in non_tool_injections if finding.target_type == CapabilityTarget.RESOURCE)
        high_severity_findings = sum(
            1 for finding in capability_findings if finding.severity == InjectionSeverity.HIGH.value
        ) + sum(1 for finding in non_tool_injections if finding.severity == InjectionSeverity.HIGH)

        return NonToolRisk(
            composite=composite,
            capability_score=capability_score,
            injection_score=injection_score,
            prompt_findings=prompt_findings,
            resource_findings=resource_findings,
            high_severity_findings=high_severity_findings,
        )

    def _category_score(
        self,
        findings: Iterable[PermissionFinding | CapabilityFinding],
        category: PermissionCategory,
    ) -> float:
        """Return the highest-weighted score for a single permission category."""
        weight = CATEGORY_WEIGHTS[category]
        best = 0.0
        for f in findings:
            if f.category == category:
                score = weight * CONFIDENCE_MULTIPLIERS[f.confidence]
                if score > best:
                    best = score
        return best
