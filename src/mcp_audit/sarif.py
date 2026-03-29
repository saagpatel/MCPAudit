"""SARIF 2.1.0 output generator for mcp-audit findings."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from mcp_audit.models import (
    AuditReport,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
)

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Fixed rule IDs per PermissionCategory
_RULE_IDS: dict[PermissionCategory, str] = {
    PermissionCategory.FILE_READ: "MCP001",
    PermissionCategory.FILE_WRITE: "MCP002",
    PermissionCategory.NETWORK: "MCP003",
    PermissionCategory.SHELL_EXEC: "MCP004",
    PermissionCategory.DESTRUCTIVE: "MCP005",
    PermissionCategory.EXFILTRATION: "MCP006",
}

_RULE_DESCRIPTIONS: dict[PermissionCategory, str] = {
    PermissionCategory.FILE_READ: "File system read access",
    PermissionCategory.FILE_WRITE: "File system write access",
    PermissionCategory.NETWORK: "External network access",
    PermissionCategory.SHELL_EXEC: "Shell command execution",
    PermissionCategory.DESTRUCTIVE: "Destructive operations",
    PermissionCategory.EXFILTRATION: "Data exfiltration capability",
}

# Confidence levels that trigger at least a "warning" in SARIF
_HIGH_CONFIDENCE = {Confidence.DECLARED, Confidence.HIGH, Confidence.MANUAL}


class SarifGenerator:
    """Converts an AuditReport into a SARIF 2.1.0 document."""

    def generate(self, report: AuditReport) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document as a dict. Caller is responsible for writing JSON."""
        try:
            tool_version = pkg_version("mcp-audit")
        except PackageNotFoundError:
            tool_version = "0.0.0"

        return {
            "version": "2.1.0",
            "$schema": _SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-audit",
                            "version": tool_version,
                            "informationUri": "https://github.com/saagpatel/mcp-audit",
                            "rules": self._make_rules(),
                        }
                    },
                    "results": self._make_results(report),
                }
            ],
        }

    def _make_rules(self) -> list[dict[str, Any]]:
        """One driver rule per PermissionCategory."""
        return [
            {
                "id": rule_id,
                "name": cat.value.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": _RULE_DESCRIPTIONS[cat]},
                "helpUri": "https://github.com/saagpatel/mcp-audit#readme",
                "properties": {"category": cat.value},
            }
            for cat, rule_id in _RULE_IDS.items()
        ]

    def _make_results(self, report: AuditReport) -> list[dict[str, Any]]:
        """One result per (server, tool, category) triple."""
        results: list[dict[str, Any]] = []
        for audit in report.audits:
            for finding in audit.permissions:
                results.append(self._make_result(finding, audit))
        return results

    def _finding_level(self, finding: PermissionFinding, audit: ServerAudit) -> str:
        """Determine SARIF level based on composite risk score and finding confidence."""
        composite = audit.risk_score.composite if audit.risk_score else 0.0
        if composite >= 7.0:
            return "error"
        if composite >= 3.0 or finding.confidence in _HIGH_CONFIDENCE:
            return "warning"
        return "note"

    def _make_result(self, finding: PermissionFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a single SARIF result object."""
        rule_id = _RULE_IDS[finding.category]
        level = self._finding_level(finding, audit)

        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"

        msg = (
            f"Tool '{finding.tool_name}' on server '{audit.server.name}' "
            f"has {finding.category.value} capability "
            f"(confidence: {finding.confidence.value})"
        )

        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        }
