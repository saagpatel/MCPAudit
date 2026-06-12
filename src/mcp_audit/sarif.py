"""SARIF 2.1.0 output generator for mcp-audit findings."""

from __future__ import annotations

from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from mcp_audit.models import (
    ArtifactVerifyFinding,
    ArtifactVerifyKind,
    ArtifactVerifySeverity,
    AuditReport,
    CapabilityFinding,
    Confidence,
    DriftFinding,
    EgressFinding,
    EgressKind,
    EgressSeverity,
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    InjectionFinding,
    InjectionSeverity,
    IntegrityFinding,
    IntegrityKind,
    IntegritySeverity,
    PackageVerifyFinding,
    PackageVerifyKind,
    PackageVerifySeverity,
    PermissionCategory,
    PermissionFinding,
    ProvenanceFinding,
    ProvenanceKind,
    ProvenanceSeverity,
    ServerAudit,
    ShadowingFinding,
    ShadowingKind,
    ShadowingSeverity,
    SsrfFinding,
    SsrfSeverity,
    TrifectaFinding,
    TrifectaSeverity,
)
from mcp_audit.redaction import redact_data
from mcp_audit.taxonomy import (
    ARTIFACT_VERIFY_FINDINGS,
    EGRESS_FINDINGS,
    ESCALATION_FINDINGS,
    INJECTION_FINDINGS,
    INTEGRITY_FINDINGS,
    PACKAGE_VERIFY_FINDINGS,
    PERMISSION_FINDINGS,
    PROVENANCE_FINDINGS,
    SHADOWING_FINDINGS,
    SSRF_FINDINGS,
    TRIFECTA_FINDINGS,
    format_rule_of_two,
)

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

# Egress-specific SARIF rule IDs (keyed by kind: MCP040 outside-allowlist, 041 unbounded, 042 residual)
_EGRESS_RULE_IDS: dict[EgressKind, str] = {
    kind: metadata.rule_id for kind, metadata in EGRESS_FINDINGS.items()
}

_EGRESS_RULE_DESCRIPTIONS = {metadata.rule_id: metadata.description for metadata in EGRESS_FINDINGS.values()}

# Trifecta-specific SARIF rule IDs
_TRIFECTA_RULE_IDS: dict[TrifectaSeverity, str] = {
    severity: metadata.rule_id for severity, metadata in TRIFECTA_FINDINGS.items()
}

_TRIFECTA_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in TRIFECTA_FINDINGS.values()
}

_DRIFT_RULE_ID = "MCP009"
_POLICY_RULE_ID = "MCP010"

# Shadowing-specific SARIF rule IDs
_SHADOWING_RULE_IDS: dict[ShadowingKind, str] = {
    kind: metadata.rule_id for kind, metadata in SHADOWING_FINDINGS.items()
}

_SHADOWING_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in SHADOWING_FINDINGS.values()
}

# Escalation-specific SARIF rule IDs (keyed by kind: MCP018 capability, MCP019 description-injection)
_ESCALATION_RULE_IDS: dict[EscalationKind, str] = {
    kind: metadata.rule_id for kind, metadata in ESCALATION_FINDINGS.items()
}

_ESCALATION_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in ESCALATION_FINDINGS.values()
}

# Provenance-specific SARIF rule IDs (keyed by kind: MCP020 command, 021 args, 022 url, 023 credentials)
_PROVENANCE_RULE_IDS: dict[ProvenanceKind, str] = {
    kind: metadata.rule_id for kind, metadata in PROVENANCE_FINDINGS.items()
}

_PROVENANCE_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in PROVENANCE_FINDINGS.values()
}

# Integrity-specific SARIF rule IDs (keyed by kind: MCP024 artifact drift)
_INTEGRITY_RULE_IDS: dict[IntegrityKind, str] = {
    kind: metadata.rule_id for kind, metadata in INTEGRITY_FINDINGS.items()
}

_INTEGRITY_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in INTEGRITY_FINDINGS.values()
}

# Package-verification SARIF rule IDs (keyed by kind: MCP025 registry hash drift)
_PACKAGE_VERIFY_RULE_IDS: dict[PackageVerifyKind, str] = {
    kind: metadata.rule_id for kind, metadata in PACKAGE_VERIFY_FINDINGS.items()
}

_PACKAGE_VERIFY_RULE_DESCRIPTIONS = {
    metadata.rule_id: metadata.description for metadata in PACKAGE_VERIFY_FINDINGS.values()
}

# Byte-level artifact-verification SARIF rule IDs (all kinds map to MCP026).
_ARTIFACT_VERIFY_RULE_IDS: dict[ArtifactVerifyKind, str] = {
    kind: metadata.rule_id for kind, metadata in ARTIFACT_VERIFY_FINDINGS.items()
}

# MCP026 covers three kinds; combine their descriptions for the single SARIF rule.
_ARTIFACT_VERIFY_RULE_DESCRIPTIONS = {
    rule_id: " ".join(
        sorted({m.description for m in ARTIFACT_VERIFY_FINDINGS.values() if m.rule_id == rule_id})
    )
    for rule_id in {m.rule_id for m in ARTIFACT_VERIFY_FINDINGS.values()}
}


def _artifact_uri(config_path: str | None) -> str:
    if not config_path:
        return "file:///unknown"
    path = Path(config_path)
    if not path.is_absolute():
        path = path.resolve()
    return path.as_uri()


class SarifGenerator:
    """Converts an AuditReport into a SARIF 2.1.0 document."""

    def generate(self, report: AuditReport) -> dict[str, Any]:
        """Return a SARIF 2.1.0 document as a dict. Caller is responsible for writing JSON."""
        report = AuditReport.model_validate(redact_data(report.model_dump(mode="json")))
        try:
            tool_version = pkg_version("mcp-audits")
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
        egress_rules = [
            {
                "id": rule_id,
                "name": f"Egress{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _egress_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "egress"},
            }
            for rule_id, desc in _EGRESS_RULE_DESCRIPTIONS.items()
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
        shadowing_rules = [
            {
                "id": rule_id,
                "name": f"Shadowing{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _shadowing_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "tool_shadowing"},
            }
            for rule_id, desc in _SHADOWING_RULE_DESCRIPTIONS.items()
        ]
        escalation_rules = [
            {
                "id": rule_id,
                "name": f"Escalation{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _escalation_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "capability_escalation"},
            }
            for rule_id, desc in _ESCALATION_RULE_DESCRIPTIONS.items()
        ]
        provenance_rules = [
            {
                "id": rule_id,
                "name": f"Provenance{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _provenance_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "provenance"},
            }
            for rule_id, desc in _PROVENANCE_RULE_DESCRIPTIONS.items()
        ]
        integrity_rules = [
            {
                "id": rule_id,
                "name": f"Integrity{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _integrity_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "integrity"},
            }
            for rule_id, desc in _INTEGRITY_RULE_DESCRIPTIONS.items()
        ]
        package_verify_rules = [
            {
                "id": rule_id,
                "name": f"PackageVerify{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _package_verify_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "package_verify"},
            }
            for rule_id, desc in _PACKAGE_VERIFY_RULE_DESCRIPTIONS.items()
        ]
        artifact_verify_rules = [
            {
                "id": rule_id,
                "name": f"ArtifactVerify{rule_id}",
                "shortDescription": {"text": desc},
                "fullDescription": {"text": desc},
                "help": {"text": _artifact_verify_help(rule_id)},
                "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
                "properties": {"category": "artifact_verify"},
            }
            for rule_id, desc in _ARTIFACT_VERIFY_RULE_DESCRIPTIONS.items()
        ]
        return (
            perm_rules
            + injection_rules
            + ssrf_rules
            + egress_rules
            + trifecta_rules
            + shadowing_rules
            + escalation_rules
            + provenance_rules
            + integrity_rules
            + package_verify_rules
            + artifact_verify_rules
            + contract_rules
        )

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
            for egress in audit.egress_findings:
                results.append(self._make_egress_result(egress, audit))
            for trifecta in audit.trifecta_findings:
                results.append(self._make_trifecta_result(trifecta, audit))
            for escalation in audit.escalation_findings:
                results.append(self._make_escalation_result(escalation, audit))
            for provenance in audit.provenance_findings:
                results.append(self._make_provenance_result(provenance, audit))
            for integrity in audit.integrity_findings:
                results.append(self._make_integrity_result(integrity, audit))
            for package_verify in audit.package_verify_findings:
                results.append(self._make_package_verify_result(package_verify, audit))
            for artifact_verify in audit.artifact_verify_findings:
                results.append(self._make_artifact_verify_result(artifact_verify, audit))
            for drift_finding in audit.drift_findings:
                results.append(self._make_drift_result(drift_finding, audit))
        for fleet_trifecta in report.fleet_trifecta_findings:
            results.append(self._make_fleet_trifecta_result(fleet_trifecta))
        for shadowing in report.shadowing_findings:
            results.append(self._make_shadowing_result(shadowing))
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

    def _egress_level(self, finding: EgressFinding) -> str:
        if finding.severity == EgressSeverity.HIGH:
            return "error"
        if finding.severity == EgressSeverity.MEDIUM:
            return "warning"
        return "note"

    def _trifecta_level(self, finding: TrifectaFinding) -> str:
        if finding.severity == TrifectaSeverity.HIGH:
            return "error"
        return "warning"

    def _shadowing_level(self, finding: ShadowingFinding) -> str:
        if finding.severity == ShadowingSeverity.HIGH:
            return "error"
        return "warning"

    def _escalation_level(self, finding: EscalationFinding) -> str:
        if finding.severity == EscalationSeverity.HIGH:
            return "error"
        return "warning"

    def _provenance_level(self, finding: ProvenanceFinding) -> str:
        if finding.severity == ProvenanceSeverity.HIGH:
            return "error"
        return "warning"

    def _integrity_level(self, finding: IntegrityFinding) -> str:
        if finding.severity == IntegritySeverity.HIGH:
            return "error"
        return "warning"

    def _package_verify_level(self, finding: PackageVerifyFinding) -> str:
        if finding.severity == PackageVerifySeverity.HIGH:
            return "error"
        return "warning"

    def _artifact_verify_level(self, finding: ArtifactVerifyFinding) -> str:
        if finding.severity == ArtifactVerifySeverity.HIGH:
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
        uri = _artifact_uri(config_path)
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
        uri = _artifact_uri(config_path)
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
        uri = _artifact_uri(config_path)

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
        uri = _artifact_uri(config_path)
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

    def _make_egress_result(self, finding: EgressFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for an egress (outbound-destination) finding."""
        rule_id = _EGRESS_RULE_IDS[finding.kind]
        level = self._egress_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        target_label = finding.target_type.value
        destination = finding.destination_host or "caller-controlled"
        msg = (
            f"Egress finding '{finding.kind.value}' detected in {target_label} "
            f"'{finding.target_name}' on server '{audit.server.name}' "
            f"(destination: {destination}): {finding.description}. "
            f"Suggested action: {finding.remediation}"
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
                "kind": finding.kind.value,
                "target_type": finding.target_type.value,
                "target_name": finding.target_name,
                "destination_host": finding.destination_host,
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
        uri = _artifact_uri(config_path)
        leg1 = "; ".join(f"{s}/{t}" for s, t in finding.leg1_contributors)
        leg2 = "; ".join(f"{s}/{t}" for s, t in finding.leg2_contributors)
        leg3 = "; ".join(f"{s}/{t}" for s, t in finding.leg3_contributors)
        msg = (
            f"Lethal trifecta detected on server '{audit.server.name}': "
            f"leg1(file_read)=[{leg1}] "
            f"leg2(untrusted_ingestion)=[{leg2}] "
            f"leg3(exfiltration)=[{leg3}]. "
            f"Suggested action: {finding.remediation}"
        )
        if finding.rule_of_two is not None:
            msg += f" {format_rule_of_two(finding.rule_of_two)}."
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
                "rule_of_two": finding.rule_of_two.model_dump() if finding.rule_of_two else None,
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
            f"leg2(untrusted_ingestion)=[{leg2}] "
            f"leg3(exfiltration)=[{leg3}]. "
            f"Suggested action: {finding.remediation}"
        )
        if finding.rule_of_two is not None:
            msg += f" {format_rule_of_two(finding.rule_of_two)}."
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
                "rule_of_two": finding.rule_of_two.model_dump() if finding.rule_of_two else None,
            },
        }

    def _make_shadowing_result(self, finding: ShadowingFinding) -> dict[str, Any]:
        """Build a SARIF result for a fleet-level shadowing finding (MCP015/016/017)."""
        rule_id = _SHADOWING_RULE_IDS[finding.kind]
        level = self._shadowing_level(finding)
        pairs = "; ".join(f"{srv}/{tool}" for srv, tool in finding.collisions)
        msg = (
            f"Tool-name shadowing ({finding.kind.value}) detected for '{finding.name}': "
            f"servers=[{pairs}]. "
            f"Suggested action: {finding.remediation}"
        )
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///unknown"}}}],
            "partialFingerprints": {"mcpAuditStableId": _stable_fingerprint(rule_id, "fleet", finding.name)},
            "properties": {
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "canonical_name": finding.name,
                "collisions": finding.collisions,
                "remediation": finding.remediation,
            },
        }

    def _make_escalation_result(self, finding: EscalationFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a per-server capability-escalation finding (MCP018/MCP019)."""
        rule_id = _ESCALATION_RULE_IDS[finding.kind]
        level = self._escalation_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        gained = (
            ", ".join(c.value for c in finding.gained_categories)
            if finding.kind == EscalationKind.CAPABILITY
            else ", ".join(finding.gained_patterns)
        )
        msg = (
            f"Capability escalation ({finding.kind.value}) on tool '{finding.tool_name}' of server "
            f"'{audit.server.name}' vs pin baseline: gained [{gained}]. "
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
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "tool_name": finding.tool_name,
                "gained_categories": [c.value for c in finding.gained_categories],
                "gained_patterns": finding.gained_patterns,
                "remediation": finding.remediation,
            },
        }

    def _make_provenance_result(self, finding: ProvenanceFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a per-server provenance finding (MCP020-023)."""
        rule_id = _PROVENANCE_RULE_IDS[finding.kind]
        level = self._provenance_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        msg = f"{finding.summary} Suggested action: {finding.remediation}"
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.kind.value)
            },
            "properties": {
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "baseline": finding.baseline,
                "current": finding.current,
                "gained_flags": finding.gained_flags,
                "remediation": finding.remediation,
            },
        }

    def _make_integrity_result(self, finding: IntegrityFinding, audit: ServerAudit) -> dict[str, Any]:
        """Build a SARIF result for a per-server launch-artifact integrity finding (MCP024)."""
        rule_id = _INTEGRITY_RULE_IDS[finding.kind]
        level = self._integrity_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        msg = f"{finding.summary} Suggested action: {finding.remediation}"
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(rule_id, audit.server.name, finding.artifact_path)
            },
            "properties": {
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "artifact_path": finding.artifact_path,
                "baseline_hash": finding.baseline_hash,
                "current_hash": finding.current_hash,
                "remediation": finding.remediation,
            },
        }

    def _make_package_verify_result(
        self, finding: PackageVerifyFinding, audit: ServerAudit
    ) -> dict[str, Any]:
        """Build a SARIF result for a registry package-verification finding (MCP025)."""
        rule_id = _PACKAGE_VERIFY_RULE_IDS[finding.kind]
        level = self._package_verify_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        msg = f"{finding.summary} Suggested action: {finding.remediation}"
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(
                    rule_id, audit.server.name, f"{finding.ecosystem}:{finding.package}:{finding.version}"
                )
            },
            "properties": {
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "ecosystem": finding.ecosystem,
                "package": finding.package,
                "version": finding.version,
                "baseline_hash": finding.baseline_hash,
                "current_hash": finding.current_hash,
                "remediation": finding.remediation,
            },
        }

    def _make_artifact_verify_result(
        self, finding: ArtifactVerifyFinding, audit: ServerAudit
    ) -> dict[str, Any]:
        """Build a SARIF result for a byte-level artifact-verification finding (MCP026)."""
        rule_id = _ARTIFACT_VERIFY_RULE_IDS[finding.kind]
        level = self._artifact_verify_level(finding)
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
        msg = f"{finding.summary} Suggested action: {finding.remediation}"
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {
                "mcpAuditStableId": _stable_fingerprint(
                    rule_id,
                    audit.server.name,
                    f"{finding.kind.value}:{finding.ecosystem}:{finding.package}:{finding.version}",
                )
            },
            "properties": {
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "ecosystem": finding.ecosystem,
                "package": finding.package,
                "version": finding.version,
                "baseline_hash": finding.baseline_hash,
                "current_hash": finding.current_hash,
                "remediation": finding.remediation,
            },
        }

    def _make_drift_result(self, finding: DriftFinding, audit: ServerAudit) -> dict[str, Any]:
        config_path = audit.server.config_path
        uri = _artifact_uri(config_path)
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


def _egress_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in EGRESS_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _trifecta_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in TRIFECTA_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _shadowing_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in SHADOWING_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _escalation_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in ESCALATION_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _provenance_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in PROVENANCE_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _integrity_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in INTEGRITY_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _package_verify_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in PACKAGE_VERIFY_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _artifact_verify_help(rule_id: str) -> str:
    remediations = {
        metadata.remediation for metadata in ARTIFACT_VERIFY_FINDINGS.values() if metadata.rule_id == rule_id
    }
    return " ".join(sorted(remediations))


def _severity_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
