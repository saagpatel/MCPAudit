"""Tests for server.py — _install_to_config and _build_mcp_server."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, InjectionFinding, InjectionSeverity, RiskScore, ServerAudit
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


# ---------------------------------------------------------------------------
# call_tool coverage for the remaining MCP tools
# ---------------------------------------------------------------------------


def _report_with(audits: list[ServerAudit]) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="test-host",
        os_platform="test-os",
        servers_discovered=len(audits),
        servers_connected=len(audits),
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.01,
    )


def _stub_run_scan(monkeypatch: pytest.MonkeyPatch, report: AuditReport) -> dict[str, ScanOptions]:
    import mcp_audit.server as server_module

    seen: dict[str, ScanOptions] = {}

    async def fake_run_scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        seen["options"] = options
        return report

    monkeypatch.setattr(server_module, "run_scan", fake_run_scan)
    return seen


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool_name", "flag", "expect_skip_connect"),
    [
        ("get_ssrf_findings", "ssrf_check", False),
        ("get_trifecta_findings", "trifecta_check", False),
        ("get_shadowing_findings", "shadow_check", False),
        ("get_escalation_findings", "escalation_check", False),
        ("get_provenance_findings", "provenance_check", False),
        ("get_integrity_findings", "integrity_check", True),
        ("get_package_verify_findings", "verify_artifacts", True),
        ("get_artifact_verify_findings", "download_artifacts", True),
    ],
)
async def test_findings_tools_thread_flags_and_return_json_lists(
    monkeypatch: pytest.MonkeyPatch, tool_name: str, flag: str, expect_skip_connect: bool
) -> None:
    """Every findings tool must enable its check flag and return a JSON list."""
    seen = _stub_run_scan(monkeypatch, _report_with([]))

    app = _build_mcp_server()
    _content, metadata = await app.call_tool(tool_name, {})

    assert json.loads(metadata["result"]) == []
    options = seen["options"]
    assert getattr(options, flag) is True
    assert options.skip_connect is expect_skip_connect


@pytest.mark.anyio
async def test_scan_mcp_servers_returns_full_report_and_threads_skip_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _stub_run_scan(monkeypatch, _report_with([]))

    app = _build_mcp_server()
    _content, metadata = await app.call_tool("scan_mcp_servers", {"skip_connect": True})

    payload = json.loads(metadata["result"])
    assert payload["schema_version"] == 1
    assert seen["options"].skip_connect is True


@pytest.mark.anyio
async def test_get_high_risk_servers_filters_by_composite(monkeypatch: pytest.MonkeyPatch) -> None:
    def _score(composite: float) -> RiskScore:
        return RiskScore(
            composite=composite,
            file_access=0.0,
            network_access=0.0,
            shell_execution=0.0,
            destructive=0.0,
            exfiltration=0.0,
        )

    audits = [
        ServerAudit(
            server=make_server_config(name="risky"),
            connection_status="connected",
            risk_score=_score(9.1),
        ),
        ServerAudit(
            server=make_server_config(name="tame"),
            connection_status="connected",
            risk_score=_score(3.0),
        ),
        ServerAudit(server=make_server_config(name="unscored"), connection_status="failed"),
    ]
    _stub_run_scan(monkeypatch, _report_with(audits))

    app = _build_mcp_server()
    _content, metadata = await app.call_tool("get_high_risk_servers", {})

    assert json.loads(metadata["result"]) == [{"name": "risky", "score": 9.1}]


@pytest.mark.anyio
async def test_check_server_returns_single_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    audits = [
        ServerAudit(server=make_server_config(name="srv1"), connection_status="connected"),
        ServerAudit(server=make_server_config(name="srv2"), connection_status="connected"),
    ]
    _stub_run_scan(monkeypatch, _report_with(audits))

    app = _build_mcp_server()
    _content, metadata = await app.call_tool("check_server", {"name": "srv2"})

    payload = json.loads(metadata["result"])
    assert payload["server"]["name"] == "srv2"


@pytest.mark.anyio
async def test_check_server_unknown_name_is_a_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown server name must surface as an MCP tool error (isError), not a
    successful call whose payload happens to contain an 'error' key."""
    from mcp.server.fastmcp.exceptions import ToolError

    _stub_run_scan(monkeypatch, _report_with([]))

    app = _build_mcp_server()
    with pytest.raises(ToolError, match="not found"):
        await app.call_tool("check_server", {"name": "ghost"})


@pytest.mark.anyio
async def test_list_discovered_servers_lists_configs(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.server as server_module

    monkeypatch.setattr(server_module, "discover_all_configs", lambda clients: [make_server_config(name="a")])

    app = _build_mcp_server()
    _content, metadata = await app.call_tool("list_discovered_servers", {})

    assert json.loads(metadata["result"]) == [{"name": "a", "client": "claude_code", "transport": "stdio"}]
