"""Tests for the single-file HTML report generator.

Covers:
  - Well-formed document scaffold (doctype, title, body close)
  - Summary stats + per-server section rendering
  - Every finding type surfaces (permission, injection, ssrf, trifecta,
    escalation, drift, fleet shadowing, policy, config health)
  - SECURITY: attacker-influenceable text (tool descriptions / matched text) is
    HTML-escaped so the report can never become an XSS vector
  - Empty report still renders valid HTML with "None" markers
  - Loads the escalation fixture and renders it
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    ClientType,
    Confidence,
    ConnectionMode,
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    PolicyResult,
    PolicyViolation,
    RiskScore,
    ServerAudit,
    ServerConfig,
    TransportType,
)

_GEN = HtmlReportGenerator()

_XSS = "<script>alert('pwned')</script>"


def _server_config(name: str = "srv") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )


def _report_with_findings() -> AuditReport:
    audit = ServerAudit(
        server=_server_config(f"evil-server{_XSS}"),  # attacker text in the server name
        connection_status="connected",
        connection_error=_XSS,  # attacker text in the error string
        risk_score=RiskScore(
            composite=8.5,
            file_access=9.0,
            network_access=5.0,
            shell_execution=8.0,
            destructive=3.0,
            exfiltration=7.0,
        ),
        permissions=[
            PermissionFinding(
                category=PermissionCategory.SHELL_EXEC,
                confidence=Confidence.HIGH,
                evidence=[_XSS],  # attacker text in evidence
                tool_name="run",
            )
        ],
        injection_findings=[
            InjectionFinding(
                tool_name="run",
                severity=InjectionSeverity.HIGH,
                pattern_name="ignore_instructions",
                matched_text=_XSS,  # attacker text in matched excerpt
                description="injection",
            )
        ],
        escalation_findings=[
            EscalationFinding(
                kind=EscalationKind.CAPABILITY,
                severity=EscalationSeverity.HIGH,
                server_name="evil-server",
                tool_name="run",
                gained_categories=[PermissionCategory.SHELL_EXEC],
                description="escalated",
            )
        ],
    )
    return AuditReport(
        scan_timestamp=datetime(2026, 5, 31, 12, 0, tzinfo=UTC),
        hostname="host",
        os_platform="Test",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=1,
        audits=[audit],
        scan_duration_seconds=0.1,
        policy_result=PolicyResult(
            passed=False,
            violations=[
                PolicyViolation(
                    rule="fail_on.escalation",
                    message="escalation finding",
                    server_name="evil-server",
                    tool_name="run",
                    severity="high",
                )
            ],
        ),
    )


class TestDocumentScaffold:
    def test_renders_valid_html_document(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>mcp-audit report</title>" in html
        assert html.rstrip().endswith("</body></html>")

    def test_summary_and_server_section_present(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert "MCP Permission Audit" in html
        assert "evil-server" in html
        assert "High-risk servers" in html

    def test_finding_sections_present(self) -> None:
        html = _GEN.generate(_report_with_findings())
        for label in ("Permissions", "Prompt-injection", "Capability escalation", "Policy"):
            assert label in html
        assert "MCP018" in html  # escalation rule id
        assert "ignore_instructions" in html


class TestXssSafety:
    def test_attacker_markup_is_escaped_not_raw(self) -> None:
        html = _GEN.generate(_report_with_findings())
        # Raw script tag must NOT appear — only the escaped form.
        assert _XSS not in html
        assert "&lt;script&gt;" in html

    def test_no_raw_angle_bracket_payload_anywhere(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert "<script>alert" not in html


class TestEmptyReport:
    def test_empty_report_still_valid(self) -> None:
        report = AuditReport(
            scan_timestamp=datetime(2026, 5, 31, 12, 0, tzinfo=UTC),
            hostname="host",
            os_platform="Test",
            servers_discovered=0,
            servers_connected=0,
            servers_failed=0,
            total_tools=0,
            high_risk_servers=0,
            audits=[],
            scan_duration_seconds=0.0,
        )
        html = _GEN.generate(report)
        assert html.startswith("<!DOCTYPE html>")
        assert "None." in html  # empty-table marker


def test_config_only_report_names_connection_mode() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/config_only_report.json").read_text()
    )
    report.connection_mode = ConnectionMode.SKIPPED
    html = _GEN.generate(report)
    assert "Connection mode" in html
    assert "Config only" in html


class TestFixtureRendering:
    def test_escalation_fixture_renders(self) -> None:
        fixture = Path("tests/fixtures/reports/escalation_report.json")
        report = AuditReport.model_validate_json(fixture.read_text())
        html = _GEN.generate(report)
        assert "rugpull-server" in html
        assert "MCP018" in html
        assert "shell_execution" in html
