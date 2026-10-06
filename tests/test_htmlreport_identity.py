"""Regression coverage for identity-preserving HTML display redaction."""

from pathlib import Path

import pytest

from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ClientType,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
    ServerConfig,
    TransportType,
)
from mcp_audit.ux_summary import actions


@pytest.mark.parametrize("home_root", ["/Users", "/home"])
def test_identifier_redaction_preserves_action_identity_and_grade(home_root: str) -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    report.coverage["metadata"] = CheckCoverage(state="complete", reason="synthetic fixture check completed")
    report.audits = [
        ServerAudit(
            server=ServerConfig(
                name="shared-server",
                client=ClientType.CLAUDE_CODE,
                config_path=f"{home_root}/{user}/mcp.json",
                transport=TransportType.STDIO,
            ),
            connection_status="connected",
            permissions=[
                PermissionFinding(
                    category=PermissionCategory.SHELL_EXEC,
                    confidence=Confidence.HIGH,
                    evidence=["run"],
                    tool_name="run",
                )
            ],
        )
        for user in ("synthetic-user-a", "synthetic-user-b")
    ]
    report.config_health_findings = []
    report.fleet_trifecta_findings = []
    report.shadowing_findings = []
    report.policy_result = None
    report.servers_discovered = report.servers_connected = 2
    report.total_tools = report.high_risk_servers = 0
    original = report.model_dump(mode="json")
    assert len(actions(report)) == 2
    assert report.ux_summary["grade"] == "D"

    for show_host in (False, True):
        html = HtmlReportGenerator().generate(report, show_host=show_host)
        assert 'aria-label="Grade D"' in html
        assert "Top fixes · 2" in html
        assert html.count('<article class="action">') == 2
        assert "2 actions need your review before use." in html
        assert "Estimated initial review: 10 minutes" in html
        for user in ("synthetic-user-a", "synthetic-user-b"):
            assert (f"{home_root}/{user}/mcp.json" in html) == show_host
        if not show_host:
            assert (
                html.count(f"MCP004: shared-server (claude_code, {home_root}/&lt;redacted&gt;/mcp.json)") == 2
            )
    assert report.model_dump(mode="json") == original
