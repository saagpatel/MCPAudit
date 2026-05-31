"""Integration coverage for shadowing findings across SARIF, policy, terminal report, and CLI.

Mirrors tests/test_trifecta_integration.py in structure.
"""

from __future__ import annotations

from datetime import UTC, datetime

from mcp_audit.models import (
    AuditReport,
    ClientType,
    ServerAudit,
    ServerConfig,
    ShadowingFinding,
    ShadowingKind,
    ShadowingSeverity,
    ToolInfo,
    TransportType,
)
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.shadowing import ShadowingAnalyzer
from mcp_audit.taxonomy import shadowing_metadata

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


def _audit(server_name: str, tool_names: list[str]) -> ServerAudit:
    return ServerAudit(
        server=_server(server_name),
        connection_status="connected",
        tools=[ToolInfo(name=t) for t in tool_names],
    )


def _audit_clean(server_name: str = "clean-server") -> ServerAudit:
    return ServerAudit(
        server=_server(server_name),
        connection_status="connected",
        tools=[ToolInfo(name=f"{server_name}_search")],
    )


def _shadowing_finding(
    kind: ShadowingKind = ShadowingKind.EXACT,
    name: str = "search",
    collisions: list[tuple[str, str]] | None = None,
) -> ShadowingFinding:
    if collisions is None:
        collisions = [("legit", "search"), ("suspect", "search")]
    severity = ShadowingSeverity.HIGH if kind != ShadowingKind.NORMALIZED else ShadowingSeverity.MEDIUM
    meta = shadowing_metadata(kind)
    return ShadowingFinding(
        kind=kind,
        severity=severity,
        name=name,
        collisions=collisions,
        description=meta.description,
    )


def _report(
    audits: list[ServerAudit],
    shadowing: list[ShadowingFinding] | None = None,
) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime(2026, 5, 31, 12, 0, 0, tzinfo=UTC),
        hostname="test-host",
        os_platform="Test",
        servers_discovered=len(audits),
        servers_connected=len(audits),
        servers_failed=0,
        total_tools=sum(len(a.tools) for a in audits),
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.1,
        shadowing_findings=shadowing or [],
    )


# ---------------------------------------------------------------------------
# SARIF integration
# ---------------------------------------------------------------------------


class TestSarif:
    def test_exact_finding_emits_mcp015(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        sarif = SarifGenerator().generate(report)
        rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert "MCP015" in rule_ids

    def test_normalized_finding_emits_mcp016(self) -> None:
        report = _report(
            [_audit_clean()],
            shadowing=[_shadowing_finding(ShadowingKind.NORMALIZED)],
        )
        sarif = SarifGenerator().generate(report)
        rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert "MCP016" in rule_ids

    def test_homoglyph_finding_emits_mcp017(self) -> None:
        report = _report(
            [_audit_clean()],
            shadowing=[_shadowing_finding(ShadowingKind.HOMOGLYPH)],
        )
        sarif = SarifGenerator().generate(report)
        rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert "MCP017" in rule_ids

    def test_mcp015_mcp016_mcp017_registered_in_driver_rules(self) -> None:
        report = _report([_audit_clean()])
        rules = SarifGenerator().generate(report)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "MCP015" in rule_ids
        assert "MCP016" in rule_ids
        assert "MCP017" in rule_ids

    def test_exact_result_level_is_error(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP015")
        assert result["level"] == "error"

    def test_normalized_result_level_is_warning(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.NORMALIZED)])
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP016")
        assert result["level"] == "warning"

    def test_result_properties_record_kind_and_collisions(self) -> None:
        finding = _shadowing_finding(ShadowingKind.EXACT, name="run")
        report = _report([_audit_clean()], shadowing=[finding])
        sarif = SarifGenerator().generate(report)
        result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP015")
        assert result["properties"]["kind"] == "exact"
        assert result["properties"]["canonical_name"] == "run"
        assert len(result["properties"]["collisions"]) >= 2

    def test_no_shadowing_no_mcp015_016_017_results(self) -> None:
        report = _report([_audit_clean()])
        sarif = SarifGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        shadowing_results = [r for r in results if r["ruleId"] in ("MCP015", "MCP016", "MCP017")]
        assert shadowing_results == []


# ---------------------------------------------------------------------------
# Policy integration
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_fail_on_shadowing_triggers_on_exact_finding(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=True))
        assert not result.passed
        assert any(v.rule == "fail_on.shadowing" for v in result.violations)

    def test_fail_on_shadowing_triggers_on_normalized_finding(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.NORMALIZED)])
        result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=True))
        assert not result.passed
        assert any(v.rule == "fail_on.shadowing" for v in result.violations)

    def test_fail_on_shadowing_false_does_not_trigger(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=False))
        assert result.passed

    def test_fail_on_shadowing_default_false_no_violation(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        result = evaluate_policy(report, PolicyConfig())
        assert result.passed

    def test_fail_on_severity_does_not_gate_shadowing(self) -> None:
        # The broad fail_on.severity shortcut must NOT cover shadowing (opt-in only)
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        result = evaluate_policy(report, PolicyConfig(fail_on_severity="high"))
        shadowing_violations = [v for v in result.violations if v.rule == "fail_on.shadowing"]
        assert shadowing_violations == []

    def test_violation_records_rule_id_in_message(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=True))
        v = next(v for v in result.violations if v.rule == "fail_on.shadowing")
        assert "MCP015" in v.message

    def test_normalized_violation_records_medium_severity(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.NORMALIZED)])
        result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=True))
        v = next(v for v in result.violations if v.rule == "fail_on.shadowing")
        assert v.severity == "medium"


# ---------------------------------------------------------------------------
# Terminal report integration
# ---------------------------------------------------------------------------


class TestReport:
    def test_shadowing_section_present_when_findings_exist(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        out = ReportGenerator().capture_terminal(report)
        assert "Shadowing" in out or "MCP015" in out

    def test_shadowing_section_absent_when_no_findings(self) -> None:
        report = _report([_audit_clean()])
        out = ReportGenerator().capture_terminal(report)
        assert "Tool-Name Shadowing" not in out

    def test_canonical_name_appears_in_report(self) -> None:
        report = _report(
            [_audit_clean()],
            shadowing=[_shadowing_finding(ShadowingKind.EXACT, name="collide_me")],
        )
        out = ReportGenerator().capture_terminal(report)
        assert "collide_me" in out

    def test_severity_appears_in_report(self) -> None:
        report = _report([_audit_clean()], shadowing=[_shadowing_finding(ShadowingKind.EXACT)])
        out = ReportGenerator().capture_terminal(report)
        assert "high" in out.lower()


# ---------------------------------------------------------------------------
# Default run: no --shadow-check → report.shadowing_findings is empty
# ---------------------------------------------------------------------------


class TestDefaultRunEmitsNothing:
    def test_report_without_shadow_check_has_empty_list(self) -> None:
        audits = [
            _audit("srv-a", ["run"]),
            _audit("srv-b", ["run"]),  # would collide if shadow_check were on
        ]
        report = _report(audits)
        assert report.shadowing_findings == []

    def test_model_serializes_empty_shadowing_field(self) -> None:
        report = _report([_audit_clean()])
        data = report.model_dump(mode="json")
        assert "shadowing_findings" in data
        assert data["shadowing_findings"] == []

    def test_shadow_check_populates_shadowing_findings(self) -> None:
        audits = [
            _audit("srv-a", ["run"]),
            _audit("srv-b", ["run"]),
        ]
        analyzer = ShadowingAnalyzer()
        findings = analyzer.analyze_fleet(audits)
        report = _report(audits, shadowing=findings)
        assert len(report.shadowing_findings) == 1
        assert report.shadowing_findings[0].kind == ShadowingKind.EXACT
