"""Tests for server.py — _install_to_config and _build_mcp_server."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, InjectionFinding, InjectionSeverity, ServerAudit
from mcp_audit.server import _MCP_AUDIT_SERVER_ENTRY, _build_mcp_server, _install_to_config
from tests.conftest import make_server_config


class TestInstallToConfig:
    def test_returns_false_for_missing_file(self, tmp_path: Path) -> None:
        result = _install_to_config(tmp_path / "nonexistent.json")
        assert result is False

    def test_returns_false_for_invalid_json(self, tmp_path: Path) -> None:
        cfg = tmp_path / "bad.json"
        cfg.write_text("not valid json")
        result = _install_to_config(cfg)
        assert result is False

    def test_creates_mcp_servers_key_if_missing(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"some": "key"}))
        _install_to_config(cfg)
        data = json.loads(cfg.read_text())
        assert "mcpServers" in data

    def test_adds_entry_under_mcp_servers(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        result = _install_to_config(cfg)
        assert result is True
        data = json.loads(cfg.read_text())
        assert "mcp-audit" in data["mcpServers"]
        assert data["mcpServers"]["mcp-audit"] == _MCP_AUDIT_SERVER_ENTRY

    def test_skips_if_already_registered(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        existing_entry = {"command": "mcp-audit", "args": ["serve"]}
        cfg.write_text(json.dumps({"mcpServers": {"mcp-audit": existing_entry}}))
        result = _install_to_config(cfg)
        assert result is True
        # Entry should not be changed
        data = json.loads(cfg.read_text())
        assert data["mcpServers"]["mcp-audit"] == existing_entry

    def test_preserves_existing_entries(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"mcpServers": {"other-server": {"command": "other"}}}))
        _install_to_config(cfg)
        data = json.loads(cfg.read_text())
        assert "other-server" in data["mcpServers"]
        assert "mcp-audit" in data["mcpServers"]

    def test_uses_custom_server_name(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        _install_to_config(cfg, server_name="my-audit")
        data = json.loads(cfg.read_text())
        assert "my-audit" in data["mcpServers"]
        assert "mcp-audit" not in data["mcpServers"]

    def test_returns_false_for_non_dict_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps([1, 2, 3]))
        result = _install_to_config(cfg)
        assert result is False


class TestBuildMcpServer:
    def test_returns_fastmcp_instance(self) -> None:
        app = _build_mcp_server()
        # FastMCP has list_tools method
        assert callable(getattr(app, "list_tools", None))

    def test_registers_expected_tools(self) -> None:
        app = _build_mcp_server()
        tools = asyncio.run(app.list_tools())
        tool_names = {t.name for t in tools}
        expected = {
            "scan_mcp_servers",
            "get_high_risk_servers",
            "check_server",
            "get_injection_findings",
            "list_discovered_servers",
        }
        assert expected <= tool_names

    def test_server_has_correct_name(self) -> None:
        app = _build_mcp_server()
        assert app.name == "mcp-audit"


@pytest.mark.anyio
async def test_get_injection_findings_uses_connected_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    finding = InjectionFinding(
        tool_name="evil_tool",
        severity=InjectionSeverity.HIGH,
        pattern_name="ignore_instructions",
        matched_text="ignore previous instructions",
        description="Tool description attempts to override AI instructions",
    )
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        injection_findings=[finding],
    )
    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="test-host",
        os_platform="test-os",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.01,
    )

    async def fake_run_scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        seen["options"] = options
        return report

    import mcp_audit.server as server_module

    monkeypatch.setattr(server_module, "run_scan", fake_run_scan)

    app = _build_mcp_server()
    _content, metadata = await app.call_tool("get_injection_findings", {})
    payload = json.loads(metadata["result"])

    options = seen["options"]
    assert isinstance(options, ScanOptions)
    assert options.skip_connect is False
    assert options.inject_check is True
    assert payload == [
        {
            "server": "srv",
            "tool": "evil_tool",
            "severity": "high",
            "pattern": "ignore_instructions",
            "description": "Tool description attempts to override AI instructions",
            "matched_text": "ignore previous instructions",
        }
    ]
