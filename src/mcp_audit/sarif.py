"""SARIF 2.1.0 output generator for mcp-audit findings."""

from __future__ import annotations

from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from mcp_audit.models import (
    AuditReport,
    CapabilityFinding,
    Confidence,
    DriftFinding,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
    SsrfFinding,
    SsrfSeverity,
    TrifectaFinding,
    TrifectaSeverity,
)
from mcp_audit.redaction import redact_data
from mcp_audit.taxonomy import INJECTION_FINDINGS, PERMISSION_FINDINGS, SSRF_FINDINGS, TRIFECTA_FINDINGS

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

# SSRF-specific SARIF rule IDs
_SSRF_RULE_IDS: dict[SsrfSeverity, str] = {
    severity: metadata.rule_id for severity, metadata in SSRF_FINDINGS.items()
}

_SSRF_RULE_DESCRIPTIONS = {metadata.rule_id: metadata.description for metadata in SSRF_FINDINGS.values()}

# Trifecta-specific SARIF rule IDs
_TRIFECTA_RULE_IDS: dict[TrifectaSeverity, str] = {
    severity: metadata.rule_id for severity, metadata in TRIFECTA_FINDINGS.items()
}

_TRIFECTA_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in TRIFECTA_FINDINGS.values()
}

_DRIFT_RULE_ID = "MCP009"
_POLICY_RULE_ID = "MCP010"


class SarifGenerator:
    """Converts an AuditReport into a SARIF 2.1.0 document."""

    def generate(self, report: AuditReport) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document as a dict. Caller is responsible for writing JSON."""
        report = AuditReport.model_validate(redact_data(report.model_dump(mode="json")))
        try:
            tool_version = pkg_version("mcp-permission-audit")
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
                            "informationUri": "https://github.com/saagpatel/MCPAudit",
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
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
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
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "prompt_injection"},
            }
            for rule_id, desc in _INJECTION_RULE_DESCRIPTIONS.items()
        ]
        ssrf_rules = [
            {
                "id": rule_id,
                "name": f"Ssrf{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _ssrf_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "ssrf"},
            }
            for rule_id, desc in _SSRF_RULE_DESCRIPTIONS.items()
        ]
        contract_rules = [
            {
                "id": _DRIFT_RULE_ID,
                "name": "ToolSchemaDrift",
                "shortDescription": {"text": "Tool schema drift"},
                "fullDescription": {
                    "text": "A tool was added, removed, or changed compared with the pin baseline."
                },
                "help": {"text": "Review the drift finding before refreshing the pin baseline."},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "schema_drift", "severity": "medium"},
            },
            {
                "id": _POLICY_RULE_ID,
                "name": "PolicyGateViolation",
                "shortDescription": {"text": "Policy gate violation"},
                "fullDescription": {"text": "The completed scan failed a local policy rule."},
                "help": {"text": "Review the policy violation and adjust the server or policy."},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "policy", "severity": "high"},
            },
        ]
        trifecta_rules = [
            {
                "id": rule_id,
                "name": f"Trifecta{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _trifecta_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "trifecta"},
            }
            for rule_id, desc in _TRIFECTA_RULE_DESCRIPTIONS.items()
        ]
        return perm_rules + injection_rules + ssrf_rules + trifecta_rules + contract_rules

    def _make_results(self, report: AuditReport) -> list[dict[str, Any]]:
        """One result per (server, tool, category) triple, plus injection findings."""
        results: list[dict[str, Any]] = []
        for audit in report.audits:
            for permission_finding in audit.permissions:
                results.append(self._make_result(permission_finding, audit))
            for capability_finding in audit.capability_findings:
                results.append(self._make_capability_result(capability_finding, audit))
            for inj in audit.injection_findings:
                results.append(self._make_injection_result(inj, audit))
            for ssrf in audit.ssrf_findings:
                results.append(self._make_ssrf_result(ssrf, audit))
            for trifecta in audit.trifecta_findings:
                results.append(self._make_trifecta_result(trifecta, audit))
            for drift_finding in audit.drift_findings:
                results.append(self._make_drift_result(drift_finding, audit))
        for fleet_trifecta in report.fleet_trifecta_findings:
            results.append(self._make_fleet_trifecta_result(fleet_trifecta))
        if report.policy_result is not None:
            for violation in report.policy_result.violations:
                results.append(self._make_policy_result(violation))
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

    def _ssrf_level(self, finding: SsrfFinding) -> str:
        if finding.severity == SsrfSeverity.HIGH:
            return "error"
        if finding.severity == SsrfSeverity.MEDIUM:
            return "warning"
        return "note"

    def _trifecta_level(self, finding: TrifectaFinding) -> str:
        if finding.severity == TrifectaSeverity.HIGH:
            return "error"
        return "warning"

    def _capability_level(self, finding: CapabilityFinding) -> str:
        if finding.severity == "high":
            return "error"
        if finding.severity == "medium" or finding.confidence in _HIGH_CONFIDENCE:
            return "warning"
        return "note"

    def _make_injection_result(self, finding: InjectionFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a prompt injection finding."""
        rule_id = _INJECTION_RULE_IDS[finding.severity]
        level = self._injection_level(finding)
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        target_label = finding.target_type.value
        msg = (
            f"Prompt injection pattern '{finding.pattern_name}' detected in {target_label} "
            f"'{finding.target_name or finding.tool_name}' on server '{audit.server.name}': "
            f"{finding.description}. "
            f"Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(
                    rule_id, audit.server.name, finding.target_name or finding.tool_name
                )
            },
            "properties": {
                "pattern": finding.pattern_name,
                "target_type": finding.target_type.value,
                "target_name": finding.target_name or finding.tool_name,
                "severity": finding.severity.value,
                "remediation": finding.remediation,
            },
        }

    def _make_capability_result(self, finding: CapabilityFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a prompt or resource capability finding."""
        rule_id = finding.rule_id
        level = self._capability_level(finding)
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        msg = (
            f"{finding.target_type.value.title()} '{finding.target_name}' on server "
            f"'{audit.server.name}' has {finding.category.value} capability "
            f"(confidence: {finding.confidence.value}). Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.target_name)
            },
            "properties": {
                "target_type": finding.target_type.value,
                "category": finding.category.value,
                "confidence": finding.confidence.value,
                "severity": finding.severity,
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
                "target_type": "tool",
                "target_name": finding.tool_name,
                "category": finding.category.value,
                "confidence": finding.confidence.value,
                "severity": finding.severity,
                "remediation": finding.remediation,
            },
        }

    def _make_ssrf_result(self, finding: SsrfFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for an SSRF finding."""
        rule_id = _SSRF_RULE_IDS[finding.severity]
        level = self._ssrf_level(finding)
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        target_label = finding.target_type.value
        msg = (
            f"SSRF pattern '{finding.pattern_name}' detected in {target_label} "
            f"'{finding.target_name}' on server '{audit.server.name}': "
            f"{finding.description}. Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.target_name)
            },
            "properties": {
                "pattern": finding.pattern_name,
                "target_type": finding.target_type.value,
                "target_name": finding.target_name,
                "severity": finding.severity.value,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }

    def _make_trifecta_result(self, finding: TrifectaFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a per-server trifecta finding (MCP013)."""
        rule_id = _TRIFECTA_RULE_IDS[finding.severity]
        level = self._trifecta_level(finding)
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        leg1 = "; ".join(f"{s}/{t}" for s, t in finding.leg1_contributors)
        leg2 = "; ".join(f"{s}/{t}" for s, t in finding.leg2_contributors)
        leg3 = "; ".join(f"{s}/{t}" for s, t in finding.leg3_contributors)
        msg = (
            f"Lethal trifecta detected on server '{audit.server.name}': "
            f"leg1(file_read)=[{leg1}] "
            f"leg2(network)=[{leg2}] "
            f"leg3(exfil/shell/write)=[{leg3}]. "
            f"Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, "trifecta")
            },
            "properties": {
                "target_type": "server",
                "target_name": audit.server.name,
                "severity": finding.severity.value,
                "is_fleet": False,
                "leg1_contributors": finding.leg1_contributors,
                "leg2_contributors": finding.leg2_contributors,
                "leg3_contributors": finding.leg3_contributors,
                "remediation": finding.remediation,
            },
        }

    def _make_fleet_trifecta_result(self, finding: TrifectaFinding) -> dict[str, Any]:
        """Build a SARIF result for a fleet-level trifecta advisory finding (MCP014)."""
        rule_id = _TRIFECTA_RULE_IDS[finding.severity]
        level = self._trifecta_level(finding)
        leg1 = "; ".join(f"{s}/{t}" for s, t in finding.leg1_contributors)
        leg2 = "; ".join(f"{s}/{t}" for s, t in finding.leg2_contributors)
        leg3 = "; ".join(f"{s}/{t}" for s, t in finding.leg3_contributors)
        msg = (
            f"Fleet-level lethal trifecta (advisory): "
            f"leg1(file_read)=[{leg1}] "
            f"leg2(network)=[{leg2}] "
            f"leg3(exfil/shell/write)=[{leg3}]. "
            f"Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///unknown"}}}],
            "partialFingerprints": {"mcpAuditStableId": _stable_fingerprint(rule_id, "fleet", "trifecta")},
            "properties": {
                "target_type": "fleet",
                "target_name": "fleet",
                "severity": finding.severity.value,
                "is_fleet": True,
                "leg1_contributors": finding.leg1_contributors,
                "leg2_contributors": finding.leg2_contributors,
                "leg3_contributors": finding.leg3_contributors,
                "remediation": finding.remediation,
            },
        }

    def _make_drift_result(self, finding: DriftFinding, audit: ServerAudit) -> dict[str, Any]:
        config_path = audit.server.config_path
        uri = Path(config_path).as_uri() if config_path else "file:///unknown"
        msg = (
            f"Tool '{finding.tool_name}' on server '{audit.server.name}' has "
            f"schema drift status '{finding.status.value}'. "
            f"Suggested action: {finding.remediation or 'Review before refreshing pins.'}"
        )
        return {
            "ruleId": _DRIFT_RULE_ID,
            "level": "warning",
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(_DRIFT_RULE_ID, audit.server.name, finding.tool_name)
            },
            "properties": {
                "target_type": "tool",
                "target_name": finding.tool_name,
                "status": finding.status.value,
                "remediation": finding.remediation,
            },
        }

    def _make_policy_result(self, violation: object) -> dict[str, Any]:
        from mcp_audit.models import PolicyViolation

        policy_violation = PolicyViolation.model_validate(violation)
        target = policy_violation.tool_name or policy_violation.server_name or "policy"
        msg = f"Policy rule '{policy_violation.rule}' failed: {policy_violation.message}"
        return {
            "ruleId": _POLICY_RULE_ID,
            "level": _severity_level(policy_violation.severity),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///unknown"}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(
                    _POLICY_RULE_ID, policy_violation.server_name or "policy", target
                )
            },
            "properties": {
                "rule": policy_violation.rule,
                "server_name": policy_violation.server_name,
                "tool_name": policy_violation.tool_name,
                "severity": policy_violation.severity,
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


def _ssrf_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in SSRF_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _trifecta_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in TRIFECTA_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _severity_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
