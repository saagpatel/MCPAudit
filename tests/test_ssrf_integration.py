"""Integration coverage for SSRF findings across SARIF, policy, and terminal output."""

from __future__ import annotations

from datetime import UTC, datetime

from mcp_audit.models import (
    AuditReport,
    ClientType,
    RiskScore,
    ServerAudit,
    ServerConfig,
    SsrfFinding,
    SsrfSeverity,
)
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator


def _audit(severities: list[SsrfSeverity]) -> ServerAudit:
    findings = [
        SsrfFinding(
            target_name=f"tool_{i}",
            severity=sev,
            pattern_name="url_param_with_fetch_verb" if sev is SsrfSeverity.HIGH else "url_param",
            evidence=["URL-shaped parameter 'url'"],
            description="SSRF-prone fetch capability.",
        )
        for i, sev in enumerate(severities)
    ]
    return ServerAudit(
        server=ServerConfig(
            name="webproxy",
            client=ClientType.CLAUDE_DESKTOP,
            config_path="/test/config.json",
        ),
        connection_status="connected",
        risk_score=RiskScore(
            composite=4.0,
            file_access=0.0,
            network_access=4.0,
            shell_execution=0.0,
            destructive=0.0,
            exfiltration=0.0,
        ),
        ssrf_findings=findings,
    )


def _report(audit: ServerAudit) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime(2026, 5, 4, 12, 0, 0, tzinfo=UTC),
        hostname="h",
        os_platform="Test",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.0,
    )


class TestSarif:
    def test_high_and_medium_ssrf_emit_stable_rules(self) -> None:
        report = _report(_audit([SsrfSeverity.HIGH, SsrfSeverity.MEDIUM]))
        sarif = SarifGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}
        assert "MCP011" in by_rule
        assert "MCP012" in by_rule
        assert by_rule["MCP011"]["level"] == "error"
        assert by_rule["MCP012"]["level"] == "warning"

    def test_low_ssrf_is_note_level(self) -> None:
        report = _report(_audit([SsrfSeverity.LOW]))
        results = SarifGenerator().generate(report)["runs"][0]["results"]
        ssrf = [r for r in results if r["ruleId"] == "MCP012"]
        assert len(ssrf) == 1
        assert ssrf[0]["level"] == "note"

    def test_ssrf_rules_registered_in_driver(self) -> None:
        report = _report(_audit([]))
        rules = SarifGenerator().generate(report)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert {"MCP011", "MCP012"} <= rule_ids


class TestPolicy:
    def test_fail_on_ssrf_triggers_at_threshold(self) -> None:
        report = _report(_audit([SsrfSeverity.HIGH]))
        result = evaluate_policy(report, PolicyConfig(fail_on_ssrf_severity="high"))
        assert not result.passed
        assert any(v.rule == "fail_on.ssrf" for v in result.violations)

    def test_fail_on_ssrf_below_threshold_passes(self) -> None:
        report = _report(_audit([SsrfSeverity.LOW]))
        result = evaluate_policy(report, PolicyConfig(fail_on_ssrf_severity="high"))
        assert result.passed

    def test_broad_severity_does_not_gate_ssrf(self) -> None:
        # SSRF is opt-in: the broad fail_on.severity shortcut must not gate it.
        report = _report(_audit([SsrfSeverity.HIGH]))
        result = evaluate_policy(report, PolicyConfig(fail_on_severity="low"))
        assert not any(v.rule == "fail_on.ssrf" for v in result.violations)


class TestTerminal:
    def test_ssrf_section_rendered_when_present(self) -> None:
        report = _report(_audit([SsrfSeverity.HIGH]))
        out = ReportGenerator().capture_terminal(report)
        assert "SSRF Warnings" in out
        assert "tool_0" in out

    def test_no_ssrf_section_when_absent(self) -> None:
        report = _report(_audit([]))
        out = ReportGenerator().capture_terminal(report)
        assert "SSRF Warnings" not in out
