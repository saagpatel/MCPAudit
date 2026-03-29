"""Tests for SarifGenerator."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcp_audit.models import (
    AuditReport,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
)
from mcp_audit.sarif import _INJECTION_RULE_IDS, _RULE_IDS, SarifGenerator
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
        expected = set(_RULE_IDS.values()) | set(_INJECTION_RULE_IDS.values())
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
