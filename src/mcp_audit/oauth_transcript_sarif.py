"""SARIF 2.1.0 projection for OAuth transcript findings."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from typing import Any

from mcp_audit.oauth_transcript_models import (
    FindingOutcome,
    FindingSeverity,
    OAuthTranscriptReport,
)

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_RULE_TITLES = {
    "MCPOAUTH000": "Incomplete or unverifiable OAuth transcript evidence",
    "MCPOAUTH001": "Discovery chain authority binding",
    "MCPOAUTH002": "Resource indicator and audience binding",
    "MCPOAUTH003": "Authorization response issuer binding",
    "MCPOAUTH004": "Issuer-bound client credential reuse",
    "MCPOAUTH005": "Registration method and application type",
    "MCPOAUTH006": "Protected-resource scope binding",
}


def _tool_version() -> str:
    try:
        return package_version("mcp-audits")
    except PackageNotFoundError:
        return "unknown"


def _level(severity: FindingSeverity, outcome: FindingOutcome) -> str:
    if outcome is FindingOutcome.ADVISORY:
        return "note"
    if outcome is FindingOutcome.UNKNOWN:
        return "warning"
    if severity is FindingSeverity.HIGH:
        return "error"
    if severity is FindingSeverity.MEDIUM:
        return "warning"
    return "note"


def oauth_report_to_sarif(report: OAuthTranscriptReport) -> dict[str, Any]:
    """Project the strict report through MCPAudit's established SARIF 2.1.0 shape."""
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": title},
            "helpUri": "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
        }
        for rule_id, title in sorted(_RULE_TITLES.items())
    ]
    results = []
    for finding in report.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _level(finding.severity, finding.outcome),
                "message": {
                    "text": f"{finding.title}: {'; '.join(finding.evidence)}",
                },
                "properties": {
                    "fixture_id": report.fixture_id,
                    "target": finding.target,
                    "outcome": finding.outcome.value,
                    "requirement_level": finding.requirement_level.value,
                    "spec_profile": report.spec_profile,
                    "offline_synthetic": True,
                },
            }
        )
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "version": _tool_version(),
                        "informationUri": "https://github.com/saagpatel/MCPAudit",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "report_schema": report.schema_version,
                    "verdict": report.verdict,
                    "claim_ceiling": report.claim_ceiling,
                },
            }
        ],
    }
