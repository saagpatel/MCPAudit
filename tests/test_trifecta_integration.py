"""Integration coverage for trifecta findings across SARIF, policy, terminal output, and CLI."""

from __future__ import annotations

import io
from datetime import UTC, datetime

from rich.console import Console

from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    ClientType,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
    ServerConfig,
    TransportType,
    TrifectaFinding,
    TrifectaSeverity,
)
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.trifecta import _compute_rule_of_two

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server(name: str = "test-server") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_DESKTOP,
        config_path="/test/config.json",
        transport=TransportType.STDIO,
        command="test-cmd",
    )


def _risk() -> RiskScore:
    return RiskScore(
        composite=5.0,
        file_access=5.0,
        network_access=5.0,
        shell_execution=0.0,
        destructive=0.0,
        exfiltration=0.0,
    )


def _pf(category: PermissionCategory, tool: str) -> PermissionFinding:
    return PermissionFinding(
        category=category,
        confidence=Confidence.HIGH,
        evidence=["test"],
        tool_name=tool,
    )


def _trifecta_finding(
    severity: TrifectaSeverity = TrifectaSeverity.HIGH,
    server_name: str = "test-server",
    is_fleet: bool = False,
) -> TrifectaFinding:
    from mcp_audit.taxonomy import trifecta_metadata

    meta = trifecta_metadata(severity)
    leg1 = [(server_name, "read_tool")]
    leg2 = [(server_name, "fetch_tool")]
    leg3 = [(server_name, "send_tool")]
    return TrifectaFinding(
        severity=severity,
        leg1_contributors=leg1,
        leg2_contributors=leg2,
        leg3_contributors=leg3,
        description=meta.description,
        is_fleet=is_fleet,
        # Mirror production: analyze_fleet attributes tools to servers, analyze_server does not.
        rule_of_two=_compute_rule_of_two(leg1, leg2, leg3, attribute_server=is_fleet),
    )


def _audit_with_trifecta(
    server_name: str = "test-server",
    severity: TrifectaSeverity = TrifectaSeverity.HIGH,
) -> ServerAudit:
    perms = [
        _pf(PermissionCategory.FILE_READ, "read_tool"),
        _pf(PermissionCategory.NETWORK, "fetch_tool"),
        _pf(PermissionCategory.EXFILTRATION, "send_tool"),
    ]
    return ServerAudit(
        server=_server(server_name),
        connection_status="connected",
        risk_score=_risk(),
        permissions=perms,
        trifecta_findings=[_trifecta_finding(severity, server_name)],
    )


def _audit_no_trifecta(server_name: str = "clean-server") -> ServerAudit:
    return ServerAudit(
        server=_server(server_name),
        connection_status="connected",
        risk_score=_risk(),
    )


def _report(
    audits: list[ServerAudit],
    fleet: list[TrifectaFinding] | None = None,
) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime(2026, 5, 31, 12, 0, 0, tzinfo=UTC),
        hostname="test-host",
        os_platform="Test",
        servers_discovered=len(audits),
        servers_connected=len(audits),
        servers_failed=0,
        total_tools=3,
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.1,
        fleet_trifecta_findings=fleet or [],
    )


# ---------------------------------------------------------------------------
# SARIF integration
# ---------------------------------------------------------------------------


class TestSarif:
    def test_per_server_finding_emits_mcp013(self) -> None:
        report = _report([_audit_with_trifecta()])
        sarif = SarifGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        trifecta_results = [r for r in results if r["ruleId"] == "MCP013"]
        assert len(trifecta_results) == 1
        assert trifecta_results[0]["level"] == "error"

    def test_fleet_finding_emits_mcp014(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        sarif = SarifGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        fleet_results = [r for r in results if r["ruleId"] == "MCP014"]
        assert len(fleet_results) == 1
        assert fleet_results[0]["level"] == "warning"

    def test_mcp013_and_mcp014_registered_in_driver_rules(self) -> None:
        report = _report([_audit_no_trifecta()])
        rules = SarifGenerator().generate(report)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "MCP013" in rule_ids
        assert "MCP014" in rule_ids

    def test_per_server_result_properties_record_contributors(self) -> None:
        report = _report([_audit_with_trifecta("my-server")])
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP013")
        assert result["properties"]["target_name"] == "my-server"
        assert result["properties"]["is_fleet"] is False
        assert len(result["properties"]["leg1_contributors"]) >= 1

    def test_fleet_result_properties_mark_is_fleet(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP014")
        assert result["properties"]["is_fleet"] is True
        assert result["properties"]["target_type"] == "fleet"

    def test_no_trifecta_no_mcp013_or_mcp014_results(self) -> None:
        report = _report([_audit_no_trifecta()])
        sarif = SarifGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        trifecta_results = [r for r in results if r["ruleId"] in ("MCP013", "MCP014")]
        assert trifecta_results == []


# ---------------------------------------------------------------------------
# Policy integration
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_fail_on_trifecta_triggers_on_per_server_finding(self) -> None:
        report = _report([_audit_with_trifecta()])
        result = evaluate_policy(report, PolicyConfig(fail_on_trifecta=True))
        assert not result.passed
        assert any(v.rule == "fail_on.trifecta" for v in result.violations)

    def test_fail_on_trifecta_triggers_on_fleet_finding(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        result = evaluate_policy(report, PolicyConfig(fail_on_trifecta=True))
        assert not result.passed
        assert any(v.rule == "fail_on.trifecta" for v in result.violations)

    def test_fail_on_trifecta_false_does_not_trigger(self) -> None:
        report = _report([_audit_with_trifecta()])
        result = evaluate_policy(report, PolicyConfig(fail_on_trifecta=False))
        assert result.passed

    def test_fail_on_trifecta_default_false_no_violation(self) -> None:
        report = _report([_audit_with_trifecta()])
        result = evaluate_policy(report, PolicyConfig())
        assert result.passed

    def test_fail_on_severity_does_not_gate_trifecta(self) -> None:
        # fail_on.severity must NOT cover trifecta (it's opt-in only)
        report = _report([_audit_with_trifecta()])
        result = evaluate_policy(report, PolicyConfig(fail_on_severity="high"))
        # Only trifecta findings present — severity gate should not fire on them
        trifecta_violations = [v for v in result.violations if v.rule == "fail_on.trifecta"]
        assert trifecta_violations == []

    def test_violation_records_correct_severity(self) -> None:
        report = _report([_audit_with_trifecta(severity=TrifectaSeverity.HIGH)])
        result = evaluate_policy(report, PolicyConfig(fail_on_trifecta=True))
        v = next(v for v in result.violations if v.rule == "fail_on.trifecta")
        assert v.severity == "high"

    def test_fleet_violation_records_medium_severity(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        result = evaluate_policy(report, PolicyConfig(fail_on_trifecta=True))
        v = next(v for v in result.violations if v.rule == "fail_on.trifecta")
        assert v.severity == "medium"


# ---------------------------------------------------------------------------
# Terminal report integration
# ---------------------------------------------------------------------------


class TestReport:
    def test_trifecta_section_present_when_findings_exist(self) -> None:
        report = _report([_audit_with_trifecta()])
        out = ReportGenerator().capture_terminal(report)
        assert "Lethal Trifecta" in out or "Trifecta" in out

    def test_trifecta_section_absent_when_no_findings(self) -> None:
        report = _report([_audit_no_trifecta()])
        out = ReportGenerator().capture_terminal(report)
        assert "Lethal Trifecta" not in out

    def test_fleet_trifecta_section_present_when_fleet_findings_exist(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        out = ReportGenerator().capture_terminal(report)
        assert "Trifecta" in out

    def test_per_server_table_shows_server_name(self) -> None:
        report = _report([_audit_with_trifecta("my-srv")])
        out = ReportGenerator().capture_terminal(report)
        assert "my-srv" in out


# ---------------------------------------------------------------------------
# Default run: no --trifecta-check → no trifecta findings in report
# ---------------------------------------------------------------------------


class TestDefaultRunEmitsNothing:
    def test_report_without_trifecta_check_has_empty_lists(self) -> None:
        # An audit with heavy permissions but no trifecta_findings populated
        audit = _audit_no_trifecta()
        report = _report([audit])
        assert audit.trifecta_findings == []
        assert report.fleet_trifecta_findings == []

    def test_model_serializes_empty_trifecta_fields(self) -> None:
        audit = _audit_no_trifecta()
        report = _report([audit])
        data = report.model_dump(mode="json")
        assert data["fleet_trifecta_findings"] == []
        assert data["audits"][0]["trifecta_findings"] == []


# ---------------------------------------------------------------------------
# Rule of Two posture rendering (D2 Phase 1)
# ---------------------------------------------------------------------------


class TestRuleOfTwoRendering:
    def test_sarif_result_carries_posture(self) -> None:
        report = _report([_audit_with_trifecta("srv")])
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP013")
        assert "Rule of Two" in result["message"]["text"]
        posture = result["properties"]["rule_of_two"]
        assert posture["recommended_drop"] == 3
        assert posture["affected_tools"] == ["send_tool"]
        assert len(posture["alternatives"]) == 2

    def test_terminal_report_shows_posture(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=200, highlight=False)
        ReportGenerator(console=console).render_terminal(_report([_audit_with_trifecta("srv")]))
        out = buf.getvalue()
        assert "Rule of Two" in out
        assert "--egress-check" in out  # Leg 3 action text

    def test_html_report_shows_posture(self) -> None:
        html = HtmlReportGenerator().generate(_report([_audit_with_trifecta("srv")]))
        assert "Rule of Two" in html

    def test_fleet_finding_posture_renders_in_sarif(self) -> None:
        fleet = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
        report = _report([_audit_no_trifecta()], fleet=fleet)
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP014")
        assert result["properties"]["rule_of_two"] is not None
        assert "Rule of Two" in result["message"]["text"]
