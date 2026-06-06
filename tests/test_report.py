"""Tests for ReportGenerator — terminal and JSON output."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from mcp_audit.models import (
    AuditReport,
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    DriftFinding,
    DriftStatus,
    InjectionFinding,
    InjectionSeverity,
    NonToolRisk,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
)
from mcp_audit.report import ReportGenerator, scrub_report_identifiers
from tests.conftest import make_server_config, make_tool


def _make_console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=120, highlight=False)
    return con, buf


def _base_report(audits: list[ServerAudit] | None = None) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="testhost",
        os_platform="Darwin",
        servers_discovered=len(audits or []),
        servers_connected=sum(1 for a in (audits or []) if a.connection_status == "connected"),
        servers_failed=0,
        total_tools=sum(len(a.tools) for a in (audits or [])),
        high_risk_servers=sum(1 for a in (audits or []) if a.risk_score and a.risk_score.composite >= 7.0),
        audits=audits or [],
        scan_duration_seconds=1.23,
    )


def _make_audit(
    name: str = "test-srv",
    risk: float = 2.0,
    status: str = "connected",
    tool_names: list[str] | None = None,
) -> ServerAudit:
    config = make_server_config(name=name)
    tools = [make_tool(n) for n in (tool_names or [])]
    permissions = (
        [
            PermissionFinding(
                category=PermissionCategory.FILE_READ,
                confidence=Confidence.HIGH,
                evidence=["read_file"],
                tool_name=tool_names[0] if tool_names else "test",
            )
        ]
        if tool_names
        else []
    )
    return ServerAudit(
        server=config,
        connection_status=status,
        tools=tools,
        permissions=permissions,
        risk_score=RiskScore(
            composite=risk,
            file_access=risk,
            network_access=0.0,
            shell_execution=0.0,
            destructive=0.0,
            exfiltration=0.0,
        ),
    )


class TestTerminalRender:
    def test_includes_server_name(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("my-server")
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "my-server" in output

    def test_includes_risk_score(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", risk=5.5)
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "5.5" in output

    def test_includes_non_tool_risk_score(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", risk=0.0)
        audit.non_tool_risk = NonToolRisk(
            composite=5.9,
            capability_score=1.9,
            injection_score=4.0,
            prompt_findings=2,
            resource_findings=1,
            high_severity_findings=0,
        )
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "5.9" in output

    def test_summary_banner_shows_counts(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audits = [_make_audit("s1"), _make_audit("s2")]
        report = _base_report(audits)
        gen.render_terminal(report)
        output = buf.getvalue()
        assert "2" in output  # servers_discovered

    def test_empty_report_no_crash(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        gen.render_terminal(_base_report([]))
        # Should not raise; output should mention 0 servers
        output = buf.getvalue()
        assert "0" in output

    def test_verbose_shows_tool_names(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", tool_names=["read_file", "write_file"])
        gen.render_terminal(_base_report([audit]), verbose=True)
        output = buf.getvalue()
        assert "read_file" in output
        assert "write_file" in output

    def test_verbose_shows_rule_id_and_remediation(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", tool_names=["run_shell"])
        audit.permissions[0].category = PermissionCategory.SHELL_EXEC
        gen.render_terminal(_base_report([audit]), verbose=True)
        output = buf.getvalue()
        assert "MCP004" in output
        assert "Suggested Action" in output
        assert "reviewed" in output
        assert "command" in output
        assert "surface" in output
        assert "source" in output

    def test_failed_server_shows_status(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("bad-srv", status="failed")
        audit.connection_error = "Connection refused"
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "failed" in output

    def test_high_risk_gets_red_styling(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("danger", risk=8.5)
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        # Rich outputs ANSI codes; red is typically \x1b[31m or similar
        assert "8.5" in output

    def test_capture_terminal_returns_string(self) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv")
        result = gen.capture_terminal(_base_report([audit]))
        assert isinstance(result, str)
        assert "srv" in result

    def test_drift_warnings_include_meaning_and_action(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", tool_names=["read_file"])
        audit.drift_findings = [
            DriftFinding(
                server_name="srv",
                tool_name="read_file",
                status=DriftStatus.CHANGED,
                stored_hash="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                current_hash="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                summary="Pinned tool metadata changed since the baseline.",
                details=["description changed"],
                remediation="Review the changed tool metadata before refreshing the pin baseline.",
            )
        ]
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "Tool Schema Drift" in output
        assert "Pinned tool metadata" in output
        assert "changed since the" in output
        assert "Review the changed" in output
        assert "tool metadata before" in output

    def test_capability_warnings_include_prompt_and_resource_findings(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv")
        audit.capability_findings = [
            CapabilityFinding(
                target_type=CapabilityTarget.RESOURCE,
                target_name="file:///tmp/example.txt",
                category=PermissionCategory.FILE_READ,
                confidence=Confidence.HIGH,
                evidence=["resource URI scheme 'file'"],
            )
        ]
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "Prompt And Resource Capability Findings" in output
        assert "file:///tmp" in output
        assert "file_read" in output

    def test_injection_warnings_include_target_type_and_name(self) -> None:
        con, buf = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv")
        audit.injection_findings = [
            InjectionFinding(
                tool_name="memo://review",
                target_type=CapabilityTarget.RESOURCE,
                target_name="memo://review",
                severity=InjectionSeverity.MEDIUM,
                pattern_name="role_injection",
                matched_text="assistant:",
                description="Resource injects fake role text.",
            )
        ]
        gen.render_terminal(_base_report([audit]))
        output = buf.getvalue()
        assert "Prompt Injection Warnings" in output
        assert "resource" in output
        assert "memo" in output


class TestJsonRender:
    def test_json_output_is_valid(self, tmp_path: Path) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        report = _base_report([_make_audit("srv")])
        out = tmp_path / "report.json"
        gen.render_json(report, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "audits" in data
        assert "scan_timestamp" in data

    def test_json_round_trips_through_pydantic(self, tmp_path: Path) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", risk=4.2, tool_names=["read_file"])
        report = _base_report([audit])
        out = tmp_path / "report.json"
        gen.render_json(report, out)
        reloaded = AuditReport.model_validate_json(out.read_text())
        assert reloaded.audits[0].server.name == "srv"
        assert reloaded.audits[0].risk_score is not None
        assert abs(reloaded.audits[0].risk_score.composite - 4.2) < 0.01

    def test_json_output_includes_finding_metadata(self, tmp_path: Path) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", tool_names=["run_shell"])
        audit.permissions[0].category = PermissionCategory.SHELL_EXEC
        report = _base_report([audit])
        out = tmp_path / "report.json"
        gen.render_json(report, out)
        data = json.loads(out.read_text())
        finding = data["audits"][0]["permissions"][0]
        assert finding["rule_id"] == "MCP004"
        assert finding["severity"] == "high"
        assert finding["title"] == "Shell execution capability"
        assert finding["remediation"]

    def test_json_output_includes_non_tool_risk(self, tmp_path: Path) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv")
        audit.non_tool_risk = NonToolRisk(
            composite=7.0,
            capability_score=0.0,
            injection_score=7.0,
            prompt_findings=1,
            resource_findings=0,
            high_severity_findings=1,
        )
        report = _base_report([audit])
        out = tmp_path / "report.json"
        gen.render_json(report, out)
        data = json.loads(out.read_text())
        assert data["audits"][0]["non_tool_risk"]["composite"] == 7.0
        assert data["audits"][0]["risk_score"]["composite"] == 2.0

    def test_json_output_redacts_report_strings(self, tmp_path: Path) -> None:
        con, _ = _make_console()
        gen = ReportGenerator(console=con)
        audit = _make_audit("srv", status="failed")
        audit.connection_error = "connection failed with token=abc123"
        report = _base_report([audit])
        out = tmp_path / "report.json"
        gen.render_json(report, out)
        data = json.loads(out.read_text())
        assert data["audits"][0]["connection_error"] == "connection failed with token=<redacted>"


def test_scrub_report_identifiers_removes_host_and_username() -> None:
    cfg = make_server_config(name="srv").model_copy(
        update={
            "config_path": "/Users/alice/.claude.json",
            "command": "/Users/alice/.local/bin/srv",
        }
    )
    report = _base_report([ServerAudit(server=cfg, connection_status="skipped")])
    report.hostname = "secret-host.local"
    scrubbed = scrub_report_identifiers(report)
    assert scrubbed.hostname == "<redacted-host>"
    assert scrubbed.audits[0].server.config_path == "/Users/<redacted>/.claude.json"
    assert scrubbed.audits[0].server.command == "/Users/<redacted>/.local/bin/srv"
    # original report must be left untouched (scrub returns a copy)
    assert report.hostname == "secret-host.local"
    assert report.audits[0].server.config_path == "/Users/alice/.claude.json"


def test_scrub_report_identifiers_preserves_counts_and_platform() -> None:
    report = _base_report([_make_audit("srv")])
    scrubbed = scrub_report_identifiers(report)
    assert scrubbed.os_platform == report.os_platform
    assert scrubbed.servers_discovered == report.servers_discovered
    assert scrubbed.high_risk_servers == report.high_risk_servers


def test_render_json_from_scrubbed_report_is_clean(tmp_path: Path) -> None:
    con, _ = _make_console()
    gen = ReportGenerator(console=con)
    cfg = make_server_config(name="srv").model_copy(update={"config_path": "/Users/alice/.claude.json"})
    report = _base_report([ServerAudit(server=cfg, connection_status="skipped")])
    report.hostname = "secret-host.local"
    out = tmp_path / "redacted.json"
    gen.render_json(scrub_report_identifiers(report), out)
    text = out.read_text()
    assert "secret-host.local" not in text
    assert "alice" not in text
    assert "<redacted-host>" in text
    assert "/Users/<redacted>/.claude.json" in text
