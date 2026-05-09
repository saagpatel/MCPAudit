"""SARIF 2.1.0 output generator for mcp-audit findings."""

from __future__ import annotations

from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from mcp_audit.models import (
    AuditReport,
    Confidence,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
)
from mcp_audit.redaction import redact_data
from mcp_audit.taxonomy import INJECTION_FINDINGS, PERMISSION_FINDINGS

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Fixed rule IDs per PermissionCategory.
_RULE_IDS: dict[PermissionCategory, str] = {
    category: metadata.rule_id for category, metadata in PERMISSION_FINDINGS.items()
}

_RULE_DESCRIPTIONS: dict[PermissionCategory, str] = {
    category: metadata.description for category, metadata in PERMISSION_FINDINGS.items()
}

# Confidence levels that trigger at least a "warning" in SARIF
_HIGH_CONFIDENCE = {Confidence.DECLARED, Confidence.HIGH, Confidence.MANUAL, Confidence.LLM}

# Injection-specific SARIF rule IDs
_INJECTION_RULE_IDS: dict[InjectionSeverity, str] = {
    severity: metadata.rule_id for severity, metadata in INJECTION_FINDINGS.items()
}

_INJECTION_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in INJECTION_FINDINGS.values()
}


class SarifGenerator:
    """Converts an AuditReport into a SARIF 2.1.0 document."""

    def generate(self, report: AuditReport) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document as a dict. Caller is responsible for writing JSON."""
        report = AuditReport.model_validate(redact_data(report.model_dump(mode="json")))
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
        """One driver rule per PermissionCategory plus injection rules MCP007/MCP008."""
        perm_rules = [
            {
                "id": rule_id,
                "name": PERMISSION_FINDINGS[cat].title.replace(" ", ""),
                "shortDescription": {"text": PERMISSION_FINDINGS[cat].title},
                "fullDescription": {"text": _RULE_DESCRIPTIONS[cat]},
                "help": {"text": PERMISSION_FINDINGS[cat].remediation},
                "helpUri": "https://github.com/saagpatel/mcp-audit#readme",
                "properties": {
                    "category": cat.value,
                    "severity": PERMISSION_FINDINGS[cat].severity,
                },
            }
            for cat, rule_id in _RULE_IDS.items()
        ]
        injection_rules = [
            {
                "id": rule_id,
                "name": f"PromptInjection{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _injection_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/mcp-audit#readme",
                "properties": {"category": "prompt_injection"},
            }
            for rule_id, desc in _INJECTION_RULE_DESCRIPTIONS.items()
        ]
        return perm_rules + injection_rules

    def _make_results(self, report: AuditReport) -> list[dict[str, Any]]:
        """One result per (server, tool, category) triple, plus injection findings."""
        results: list[dict[str, Any]] = []
        for audit in report.audits:
            for finding in audit.permissions:
                results.append(self._make_result(finding, audit))
            for inj in audit.injection_findings:
                results.append(self._make_injection_result(inj, audit))
        return results

    def _finding_level(self, finding: PermissionFinding, audit: ServerAudit) -> str:
        """Determine SARIF level based on composite risk score and finding confidence."""
        composite = audit.risk_score.composite if audit.risk_score else 0.0
        if composite >= 7.0:
            return "error"
        if composite >= 3.0 or finding.confidence in _HIGH_CONFIDENCE:
            return "warning"
        return "note"

    def _injection_level(self, finding: InjectionFinding) -> str:
        if finding.severity == InjectionSeverity.HIGH:
            return "error"
        if finding.severity == InjectionSeverity.MEDIUM:
            return "warning"
        return "note"

    def _make_injection_result(self, finding: InjectionFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a prompt injection finding."""
        rule_id = _INJECTION_RULE_IDS[finding.severity]
        level = self._injection_level(finding)
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        msg = (
            f"Prompt injection pattern '{finding.pattern_name}' detected in tool "
            f"'{finding.tool_name}' on server '{audit.server.name}': {finding.description}. "
            f"Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.tool_name)
            },
            "properties": {
                "pattern": finding.pattern_name,
                "severity": finding.severity.value,
                "remediation": finding.remediation,
            },
        }

    def _make_result(self, finding: PermissionFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a single SARIF result object."""
        rule_id = finding.rule_id
        level = self._finding_level(finding, audit)

        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"

        msg = (
            f"Tool '{finding.tool_name}' on server '{audit.server.name}' "
            f"has {finding.category.value} capability "
            f"(confidence: {finding.confidence.value}). Suggested action: {finding.remediation}"
        )

        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.tool_name)
            },
            "properties": {
                "category": finding.category.value,
                "confidence": finding.confidence.value,
                "severity": finding.severity,
                "remediation": finding.remediation,
            },
        }


def _stable_fingerprint(rule_id: str, server_name: str, tool_name: str) -> str:
    payload = f"{rule_id}\0{server_name}\0{tool_name}".encode()
    return sha256(payload).hexdigest()


def _injection_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in INJECTION_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))
