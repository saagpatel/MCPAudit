"""Tests for SarifGenerator."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcp_audit.models import (
    AuditReport,
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    DriftFinding,
    DriftStatus,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    PolicyResult,
    PolicyViolation,
    RiskScore,
    ServerAudit,
)
from mcp_audit.sarif import (
    _ESCALATION_RULE_IDS,
    _INJECTION_RULE_IDS,
    _INTEGRITY_RULE_IDS,
    _PACKAGE_VERIFY_RULE_IDS,
    _PROVENANCE_RULE_IDS,
    _RULE_IDS,
    _SHADOWING_RULE_IDS,
    _SSRF_RULE_IDS,
    _TRIFECTA_RULE_IDS,
    SarifGenerator,
)
from tests.conftest import make_server_config


def _make_report(audits: list[ServerAudit]) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="test",
        os_platform="Darwin",
        servers_discovered=len(audits),
        servers_connected=len(audits),
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.1,
    )


def _make_audit(
    name: str = "srv",
    risk: float = 2.0,
    findings: list[PermissionFinding] | None = None,
) -> ServerAudit:
    config = make_server_config(name=name)
    return ServerAudit(
        server=config,
        connection_status="connected",
        permissions=findings or [],
        risk_score=RiskScore(
            composite=risk,
            file_access=0.0,
            network_access=0.0,
            shell_execution=0.0,
            destructive=0.0,
            exfiltration=0.0,
        ),
    )


def _finding(
    cat: PermissionCategory = PermissionCategory.SHELL_EXEC,
    conf: Confidence = Confidence.HIGH,
    tool: str = "tool1",
) -> PermissionFinding:
    return PermissionFinding(category=cat, confidence=conf, evidence=["test"], tool_name=tool)


class TestSarifStructure:
    def test_version_is_2_1_0(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        assert sarif["version"] == "2.1.0"

    def test_has_runs_key(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_driver_name(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "mcp-audit"

    def test_all_rules_present(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        expected = (
            set(_RULE_IDS.values())
            | set(_INJECTION_RULE_IDS.values())
            | set(_SSRF_RULE_IDS.values())
            | set(_TRIFECTA_RULE_IDS.values())
            | set(_SHADOWING_RULE_IDS.values())
            | set(_ESCALATION_RULE_IDS.values())
            | set(_PROVENANCE_RULE_IDS.values())
            | set(_INTEGRITY_RULE_IDS.values())
            | set(_PACKAGE_VERIFY_RULE_IDS.values())
            | {"MCP009", "MCP010"}
        )
        assert rule_ids == expected

    def test_empty_report_has_empty_results(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        assert sarif["runs"][0]["results"] == []

    def test_round_trips_json(self) -> None:
        audit = _make_audit(findings=[_finding()])
        sarif = SarifGenerator().generate(_make_report([audit]))
        # Should not raise
        reloaded = json.loads(json.dumps(sarif))
        assert reloaded["version"] == "2.1.0"


class TestSarifResults:
    def test_result_count_matches_findings(self) -> None:
        findings = [
            _finding(PermissionCategory.SHELL_EXEC),
            _finding(PermissionCategory.NETWORK),
            _finding(PermissionCategory.FILE_READ),
        ]
        audit = _make_audit(findings=findings)
        sarif = SarifGenerator().generate(_make_report([audit]))
        assert len(sarif["runs"][0]["results"]) == 3

    def test_capability_finding_emits_sarif_result(self) -> None:
        audit = _make_audit()
        audit.capability_findings = [
            CapabilityFinding(
                target_type=CapabilityTarget.RESOURCE,
                target_name="file:///tmp/example.txt",
                category=PermissionCategory.FILE_READ,
                confidence=Confidence.HIGH,
                evidence=["resource URI scheme 'file'"],
            )
        ]
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP001"
        assert result["properties"]["target_type"] == "resource"
        assert "file:///tmp/example.txt" in result["message"]["text"]

    def test_injection_finding_emits_target_metadata(self) -> None:
        audit = _make_audit()
        audit.injection_findings = [
            InjectionFinding(
                tool_name="prompt://review",
                target_type=CapabilityTarget.PROMPT,
                target_name="review_prompt",
                severity=InjectionSeverity.MEDIUM,
                pattern_name="role_injection",
                matched_text="assistant:",
                description="Prompt injects fake role text.",
            )
        ]
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP008"
        assert result["properties"]["target_type"] == "prompt"
        assert result["properties"]["target_name"] == "review_prompt"
        assert "prompt 'review_prompt'" in result["message"]["text"]

    def test_integrity_finding_emits_sarif_result(self) -> None:
        from mcp_audit.models import IntegrityFinding, IntegrityKind, IntegritySeverity

        audit = _make_audit()
        audit.integrity_findings = [
            IntegrityFinding(
                kind=IntegrityKind.ARTIFACT_DRIFT,
                severity=IntegritySeverity.HIGH,
                server_name="srv",
                artifact_path="/usr/local/bin/mcp-server",
                baseline_hash="a" * 64,
                current_hash="b" * 64,
                summary="Launch artifact changed.",
            )
        ]
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP024"
        assert result["level"] == "error"
        assert result["properties"]["artifact_path"] == "/usr/local/bin/mcp-server"
        assert result["properties"]["baseline_hash"] == "a" * 64

    def test_package_verify_finding_emits_sarif_result(self) -> None:
        from mcp_audit.models import PackageVerifyFinding, PackageVerifyKind, PackageVerifySeverity

        audit = _make_audit()
        audit.package_verify_findings = [
            PackageVerifyFinding(
                kind=PackageVerifyKind.REGISTRY_DRIFT,
                severity=PackageVerifySeverity.HIGH,
                server_name="srv",
                ecosystem="npm",
                package="server-fs",
                version="1.2.3",
                baseline_hash="sha512-OLD",
                current_hash="sha512-NEW",
                summary="Registry hash changed.",
            )
        ]
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP025"
        assert result["level"] == "error"
        assert result["properties"]["package"] == "server-fs"
        assert result["properties"]["ecosystem"] == "npm"

    def test_drift_finding_emits_sarif_result(self) -> None:
        audit = _make_audit()
        audit.drift_findings = [
            DriftFinding(server_name="srv", tool_name="read_file", status=DriftStatus.CHANGED)
        ]
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP009"
        assert result["properties"]["target_type"] == "tool"
        assert result["properties"]["target_name"] == "read_file"
        assert result["properties"]["status"] == "changed"

    def test_policy_violation_emits_sarif_result(self) -> None:
        report = _make_report([])
        report.policy_result = PolicyResult(
            passed=False,
            violations=[
                PolicyViolation(
                    rule="max_risk",
                    server_name="srv",
                    severity="high",
                    message="Server risk score 8.0 meets or exceeds policy limit 7.0.",
                )
            ],
        )
        sarif = SarifGenerator().generate(report)
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP010"
        assert result["level"] == "error"
        assert result["properties"]["rule"] == "max_risk"

    def test_high_risk_level_is_error(self) -> None:
        audit = _make_audit(risk=8.0, findings=[_finding(PermissionCategory.SHELL_EXEC)])
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_low_risk_low_confidence_is_note(self) -> None:
        audit = _make_audit(
            risk=0.5,
            findings=[_finding(PermissionCategory.FILE_READ, conf=Confidence.LOW)],
        )
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_medium_risk_is_warning(self) -> None:
        audit = _make_audit(
            risk=4.0,
            findings=[_finding(PermissionCategory.NETWORK, conf=Confidence.LOW)],
        )
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_location_uri_starts_with_file(self) -> None:
        audit = _make_audit(findings=[_finding()])
        sarif = SarifGenerator().generate(_make_report([audit]))
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("file://")

    def test_message_contains_server_name(self) -> None:
        audit = _make_audit(name="my-server", findings=[_finding()])
        sarif = SarifGenerator().generate(_make_report([audit]))
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "my-server" in msg

    def test_message_contains_tool_name(self) -> None:
        audit = _make_audit(findings=[_finding(tool="execute_command")])
        sarif = SarifGenerator().generate(_make_report([audit]))
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "execute_command" in msg

    def test_message_contains_category(self) -> None:
        audit = _make_audit(findings=[_finding(PermissionCategory.SHELL_EXEC)])
        sarif = SarifGenerator().generate(_make_report([audit]))
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "shell_execution" in msg

    def test_result_includes_remediation_and_stable_fingerprint(self) -> None:
        audit = _make_audit(findings=[_finding(PermissionCategory.SHELL_EXEC)])
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "MCP004"
        assert "Suggested action:" in result["message"]["text"]
        assert result["properties"]["target_type"] == "tool"
        assert result["properties"]["target_name"] == "tool1"
        assert result["properties"]["remediation"]
        assert result["partialFingerprints"]["mcpAuditStableId"]

    def test_rules_include_full_metadata(self) -> None:
        sarif = SarifGenerator().generate(_make_report([]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        shell_rule = next(rule for rule in rules if rule["id"] == "MCP004")
        assert shell_rule["shortDescription"]["text"] == "Shell execution capability"
        assert shell_rule["fullDescription"]["text"]
        assert shell_rule["help"]["text"]
        assert shell_rule["properties"]["severity"] == "high"

    def test_sarif_redacts_report_strings(self) -> None:
        audit = _make_audit(findings=[_finding(tool="run_shell")])
        audit.server.name = "server-with-token=abc123"
        sarif = SarifGenerator().generate(_make_report([audit]))
        result = sarif["runs"][0]["results"][0]
        assert "abc123" not in result["message"]["text"]
        assert "token=<redacted>" in result["message"]["text"]
