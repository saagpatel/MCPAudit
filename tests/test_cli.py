"""Tests for CLI orchestration helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import anyio
from click.testing import CliRunner

from mcp_audit import cli
from mcp_audit.models import AuditReport, ServerAudit
from mcp_audit.pinning import PinStore
from tests.conftest import make_server_config, make_tool


def _report(audits: list[ServerAudit]) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="test-host",
        os_platform="test-os",
        servers_discovered=len(audits),
        servers_connected=sum(1 for audit in audits if audit.connection_status == "connected"),
        servers_failed=sum(1 for audit in audits if audit.connection_status in ("failed", "timeout")),
        total_tools=sum(len(audit.tools) for audit in audits),
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.01,
    )


def test_version_option_reports_installed_distribution_version() -> None:
    result = CliRunner().invoke(cli.main, ["--version"])

    assert result.exit_code == 0
    assert "mcp-audit, version " in result.output
    assert "1.0.0a4" in result.output


def test_run_pin_connects_before_pinning(monkeypatch: object, tmp_path: Path) -> None:
    store = PinStore(path=tmp_path / "pins.yaml")
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("read_file")],
    )
    seen_skip_connect: list[bool] = []

    async def fake_run_scan_core(skip_connect: bool, *args: object, **kwargs: object) -> AuditReport:
        seen_skip_connect.append(skip_connect)
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    anyio.run(cli._run_pin, None, store)

    assert seen_skip_connect == [False]
    assert store.tool_count("srv") == 1


def test_run_pin_skips_failed_connections(monkeypatch: object, tmp_path: Path) -> None:
    store = PinStore(path=tmp_path / "pins.yaml")
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="failed",
        connection_error="boom",
    )

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    anyio.run(cli._run_pin, None, store)

    assert store.tool_count("srv") == 0


def test_pin_status_reports_pin_coverage(tmp_path: Path) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("srv", [make_tool("read_file"), make_tool("write_file")])

    result = CliRunner().invoke(cli.main, ["pin", "--status", "--pin-file", str(pin_file)])

    assert result.exit_code == 0
    assert "Pin baseline:" in result.output
    assert "1 server(s), 2 tool(s)" in result.output
    assert "srv" in result.output


def test_pin_status_json_reports_pin_coverage(tmp_path: Path) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("srv", [make_tool("read_file")])

    result = CliRunner().invoke(
        cli.main,
        ["pin", "--status", "--json", "--pin-file", str(pin_file)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["pin_file"] == str(pin_file)
    assert payload["server_count"] == 1
    assert payload["total_tools"] == 1
    assert payload["servers"][0]["name"] == "srv"
