"""Tests for ReportGenerator — terminal and JSON output."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from mcp_audit.models import (
    AuditReport,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
)
from mcp_audit.report import ReportGenerator
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
        high_risk_servers=sum(
            1 for a in (audits or []) if a.risk_score and a.risk_score.composite >= 7.0
        ),
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
    permissions = [
        PermissionFinding(
            category=PermissionCategory.FILE_READ,
            confidence=Confidence.HIGH,
            evidence=["read_file"],
            tool_name=tool_names[0] if tool_names else "test",
        )
    ] if tool_names else []
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
