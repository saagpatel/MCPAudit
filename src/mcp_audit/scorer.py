"""Risk scoring — weighted multi-dimensional scores per server."""

from mcp_audit.models import PermissionCategory, PermissionFinding, RiskScore
from mcp_audit.rules.weights import CATEGORY_WEIGHTS, CONFIDENCE_MULTIPLIERS


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
        weight = CATEGORY_WEIGHTS[category]
        best = 0.0
        for f in findings:
            if f.category == category:
                score = weight * CONFIDENCE_MULTIPLIERS[f.confidence]
                if score > best:
                    best = score
        return best
