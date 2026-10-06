"""Tests for server.py — _install_to_config and _build_mcp_server."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from mcp_audit.discovery import ConfigParseError
from mcp_audit.engine import ScanOptions
from mcp_audit.injection import InjectionDetector
from mcp_audit.models import (
    AuditReport,
    ClientType,
    InjectionFinding,
    InjectionSeverity,
    RiskScore,
    ScanWarning,
    ServerAudit,
    ServerConfig,
)
from mcp_audit.overrides import OverrideConfig, PermissionOverride, ServerToolOverride
from mcp_audit.server import _MCP_AUDIT_SERVER_ENTRY, _build_mcp_server, _install_to_config
from tests.conftest import make_server_config, make_tool


def _tool_json(result: object) -> Any:
    """Decode the stable structured result emitted by an MCPAudit tool."""
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    assert set(structured) == {"result"}
    raw = structured["result"]
    assert isinstance(raw, str)
    return json.loads(raw)


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


class TestDoInstall:
    def _patch_paths(self, monkeypatch: pytest.MonkeyPatch, desktop: list[Path], code: Path) -> None:
        import mcp_audit.server as server_module

        monkeypatch.setattr(server_module, "_CLAUDE_DESKTOP_CONFIG_PATHS", desktop)
        monkeypatch.setattr(server_module, "_CLAUDE_CODE_CONFIG_PATH", code)

    def test_found_but_unusable_config_exits_1_without_not_found_lie(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mcp_audit.server import _do_install

        broken = tmp_path / "claude_desktop_config.json"
        broken.write_text("not valid json")
        self._patch_paths(monkeypatch, [broken], tmp_path / "absent.json")

        with pytest.raises(SystemExit) as excinfo:
            _do_install()
        assert excinfo.value.code == 1
        assert "No Claude config files found" not in capsys.readouterr().out

    def test_no_configs_found_prints_manual_hint_and_exits_0(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mcp_audit.server import _do_install

        self._patch_paths(monkeypatch, [tmp_path / "a.json"], tmp_path / "b.json")
        _do_install()  # must not raise
        assert "No Claude config files found" in capsys.readouterr().out

    def test_successful_install_exits_0(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from mcp_audit.server import _do_install

        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))
        self._patch_paths(monkeypatch, [cfg], tmp_path / "absent.json")
        _do_install()  # must not raise
        assert "mcp-audit" in json.loads(cfg.read_text())["mcpServers"]


class TestBuildMcpServer:
    def test_returns_mcpserver_instance(self) -> None:
        app = _build_mcp_server()
        # MCPServer has list_tools method
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
            "get_ssrf_findings",
            "get_trifecta_findings",
            "get_shadowing_findings",
            "get_escalation_findings",
            "get_provenance_findings",
            "get_integrity_findings",
            "get_package_verify_findings",
            "get_artifact_verify_findings",
            "list_discovered_servers",
        }
        assert tool_names == expected

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
    payload = _tool_json(await app.call_tool("get_injection_findings", {}))

    options = seen["options"]
    assert isinstance(options, ScanOptions)
    assert options.skip_connect is False
    assert options.inject_check is True
    assert payload == {
        "findings": [
            {
                "server": "srv",
                "tool": "evil_tool",
                "severity": "high",
                "pattern": "ignore_instructions",
                "instruction_pattern": None,
                "hunt_targets": [],
                "field_path": None,
                "description": "Tool description attempts to override AI instructions",
                "matched_text": "ignore previous instructions",
            }
        ],
        "warnings": [],
    }


@pytest.mark.parametrize("redaction_probe", [False, True])
async def test_get_injection_findings_preserves_redacted_instruction_evidence(
    monkeypatch: pytest.MonkeyPatch,
    redaction_probe: bool,
) -> None:
    text = json.loads(Path("tests/fixtures/instruction_text.json").read_text())["poisoning"]
    assert isinstance(text, str)
    findings = InjectionDetector().scan_tool(make_tool("weather", text))
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    report.audits = report.audits[:1]
    report.audits[0].injection_findings = findings
    report.audits[0].server.name = "srv"
    if redaction_probe:
        # The projection must use report.redacted(), including the new evidence fields.
        findings[0].hunt_targets.append("password=synthetic-value")
        findings[0].field_path = "/description/password=synthetic-value"

    async def fake_run_scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        assert options.inject_check
        return report

    import mcp_audit.server as server_module

    monkeypatch.setattr(server_module, "run_scan", fake_run_scan)
    payload = _tool_json(await _build_mcp_server().call_tool("get_injection_findings", {}))
    finding = payload["findings"][0]
    assert finding["pattern"] == "INSTRUCTION_SHAPED_TEXT"
    assert finding["severity"] == "medium"
    assert finding["instruction_pattern"] == "credential_hunt"
    assert finding["hunt_targets"] == (
        ["~/.ssh/id_rsa", "password=<redacted>"] if redaction_probe else ["~/.ssh/id_rsa"]
    )
    assert finding["field_path"] == (
        "/description/password=<redacted>" if redaction_probe else "/description"
    )
    assert "synthetic-value" not in json.dumps(payload)


# ---------------------------------------------------------------------------
# call_tool coverage for the remaining MCP tools
# ---------------------------------------------------------------------------


def _report_with(audits: list[ServerAudit], warnings: list[ScanWarning] | None = None) -> AuditReport:
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
        warnings=warnings or [],
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
async def test_findings_tools_thread_flags_and_wrap_findings_with_warnings(
    monkeypatch: pytest.MonkeyPatch, tool_name: str, flag: str, expect_skip_connect: bool
) -> None:
    """Every findings tool must enable its check flag and return `{findings, warnings}`."""
    seen = _stub_run_scan(monkeypatch, _report_with([]))

    app = _build_mcp_server()
    payload = _tool_json(await app.call_tool(tool_name, {}))

    assert payload == {"findings": [], "warnings": []}
    options = seen["options"]
    assert getattr(options, flag) is True
    assert options.skip_connect is expect_skip_connect


@pytest.mark.anyio
async def test_findings_tools_surface_coverage_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty findings list with a warning must be distinguishable from 'checked, clean'."""
    warning = ScanWarning(
        code="pin_baseline_missing",
        message="--provenance-check: no pin baseline found. Run `mcp-audit pin` first.",
        check="provenance_check",
    )
    _stub_run_scan(monkeypatch, _report_with([], warnings=[warning]))

    app = _build_mcp_server()
    payload = _tool_json(await app.call_tool("get_provenance_findings", {}))
    assert payload["findings"] == []
    [emitted] = payload["warnings"]
    assert emitted["code"] == "pin_baseline_missing"
    assert emitted["check"] == "provenance_check"
    assert emitted["servers"] == []


@pytest.mark.anyio
async def test_scan_mcp_servers_returns_full_report_and_threads_skip_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _stub_run_scan(monkeypatch, _report_with([]))

    app = _build_mcp_server()
    payload = _tool_json(await app.call_tool("scan_mcp_servers", {"skip_connect": True}))
    assert payload["schema_version"] == 1
    assert seen["options"].skip_connect is True


@pytest.mark.anyio
async def test_scan_mcp_servers_still_dispatches_all_discovered_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_audit.engine as engine_module
    import mcp_audit.overrides as overrides_module
    from mcp_audit.connector import ServerConnector

    servers = [make_server_config(name="first"), make_server_config(name="second")]
    attempts: list[ServerConfig] = []

    def discover(
        clients: list[ClientType] | None = None,
        parse_errors: list[ConfigParseError] | None = None,
    ) -> list[ServerConfig]:
        assert clients is None
        assert parse_errors is not None
        return servers

    async def record_connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        attempts.append(server)
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(engine_module, "discover_all_configs", discover)
    monkeypatch.setattr(ServerConnector, "connect", record_connect)
    monkeypatch.setattr(overrides_module, "load_override_config", lambda: OverrideConfig())

    payload = _tool_json(await _build_mcp_server().call_tool("scan_mcp_servers", {}))
    assert attempts == servers
    assert [audit["server"]["name"] for audit in payload["audits"]] == ["first", "second"]


@pytest.mark.anyio
@pytest.mark.parametrize("with_warning", [False, True])
async def test_get_high_risk_servers_filters_by_composite_and_retains_list_contract(
    monkeypatch: pytest.MonkeyPatch, with_warning: bool
) -> None:
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
    warnings = (
        [ScanWarning(code="project_config_not_connected", message="Synthetic project config not connected.")]
        if with_warning
        else []
    )
    _stub_run_scan(monkeypatch, _report_with(audits, warnings=warnings))

    app = _build_mcp_server()
    payload = _tool_json(await app.call_tool("get_high_risk_servers", {}))

    assert isinstance(payload, list)
    assert payload == [{"name": "risky", "score": 9.1}]
    assert payload[0]["name"] == "risky"


@pytest.mark.anyio
async def test_get_high_risk_servers_returns_empty_list_with_coverage_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warning = ScanWarning(
        code="project_config_not_connected", message="Synthetic project config not connected."
    )
    _stub_run_scan(monkeypatch, _report_with([], warnings=[warning]))
    app = _build_mcp_server()
    assert _tool_json(await app.call_tool("get_high_risk_servers", {})) == []
    tool = next(tool for tool in await app.list_tools() if tool.name == "get_high_risk_servers")
    assert "project_config_not_connected" in tool.description
    assert "scan_mcp_servers" in tool.description
    assert "get_*_findings" in tool.description


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool_name",
    [
        "scan_mcp_servers",
        "check_server",
        "get_injection_findings",
        "get_ssrf_findings",
        "get_trifecta_findings",
        "get_shadowing_findings",
        "get_escalation_findings",
        "get_provenance_findings",
        "get_integrity_findings",
        "get_package_verify_findings",
        "get_artifact_verify_findings",
    ],
)
async def test_all_audit_tools_preserve_project_connection_warning(
    monkeypatch: pytest.MonkeyPatch, tool_name: str
) -> None:
    import mcp_audit.server as server_module

    config = make_server_config(command="synthetic-project-server")
    config.scope = "project"
    audit = ServerAudit(server=config, connection_status="skipped")
    warning = ScanWarning(
        code="project_config_not_connected",
        message="Project config not connected: synthetic-project-server. Use --connect-project-configs.",
        check="connection",
        servers=[config.name],
    )
    _stub_run_scan(monkeypatch, _report_with([audit], warnings=[warning]))
    monkeypatch.setattr(server_module, "discover_all_configs", lambda *args: [config])
    arguments = {"name": config.name} if tool_name == "check_server" else {}
    payload = _tool_json(await _build_mcp_server().call_tool(tool_name, arguments))
    assert payload["warnings"] == [warning.model_dump()]
    if tool_name == "check_server":
        assert {key: value for key, value in payload.items() if key != "warnings"} == audit.model_dump(
            mode="json"
        )
    elif tool_name.startswith("get_"):
        assert payload["findings"] == []


def _record_named_scan(
    monkeypatch: pytest.MonkeyPatch,
    servers: list[ServerConfig],
    *,
    parse_errors: list[ConfigParseError] | None = None,
    audit_for: Callable[[ServerConfig], ServerAudit] | None = None,
    overrides: OverrideConfig | None = None,
) -> list[ServerConfig]:
    """Exercise the MCP adapter and real engine without reading user configs or connecting."""
    import mcp_audit.engine as engine_module
    import mcp_audit.overrides as overrides_module
    import mcp_audit.server as server_module
    from mcp_audit.connector import ServerConnector

    def discover(
        clients: list[ClientType] | None = None,
        errors: list[ConfigParseError] | None = None,
    ) -> list[ServerConfig]:
        assert clients is None
        if errors is not None:
            errors.extend(parse_errors or [])
        return servers

    def unexpected_discovery(*args: object, **kwargs: object) -> list[ServerConfig]:
        pytest.fail("engine rediscovered the fleet")

    attempts: list[ServerConfig] = []

    async def record_connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        attempts.append(server)
        if audit_for is not None:
            return audit_for(server)
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(server_module, "discover_all_configs", discover)
    monkeypatch.setattr(engine_module, "discover_all_configs", unexpected_discovery)
    monkeypatch.setattr(ServerConnector, "connect", record_connect)
    monkeypatch.setattr(overrides_module, "load_override_config", lambda: overrides or OverrideConfig())
    return attempts


@pytest.mark.anyio
async def test_check_server_dispatches_only_unique_exact_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import mcp_audit.engine as engine_module
    import mcp_audit.overrides as overrides_module
    from mcp_audit.connector import ServerConnector
    from mcp_audit.discovery import (
        ClaudeCodeDiscoverer,
        ClaudeDesktopDiscoverer,
        CursorDiscoverer,
        VSCodeDiscoverer,
        WindsurfDiscoverer,
    )

    config = tmp_path / "claude.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "other-stdio": {"command": "synthetic-stdio"},
                    "Target": {"command": "synthetic-target"},
                    "other-http": {"type": "http", "url": "https://example.test/mcp"},
                }
            }
        )
    )
    monkeypatch.setattr(ClaudeCodeDiscoverer, "config_paths", lambda self: [config])
    for discoverer in (ClaudeDesktopDiscoverer, CursorDiscoverer, VSCodeDiscoverer, WindsurfDiscoverer):
        monkeypatch.setattr(discoverer, "config_paths", lambda self: [tmp_path / "absent.json"])

    def unexpected_discovery(*args: object, **kwargs: object) -> list[ServerConfig]:
        pytest.fail("engine rediscovered the fleet")

    attempts: list[ServerConfig] = []

    async def record_connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        attempts.append(server)
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(engine_module, "discover_all_configs", unexpected_discovery)
    monkeypatch.setattr(ServerConnector, "connect", record_connect)
    monkeypatch.setattr(overrides_module, "load_override_config", lambda: OverrideConfig())

    payload = _tool_json(await _build_mcp_server().call_tool("check_server", {"name": "Target"}))

    assert len(attempts) == 1
    assert attempts[0].name == "Target"
    assert attempts[0].config_path == str(config)
    assert payload["server"]["name"] == "Target"
    assert payload["connection_status"] == "connected"
    assert set(payload) == {
        *ServerAudit(server=attempts[0], connection_status="connected").model_dump(),
        "warnings",
    }
    assert payload["warnings"] == []
    assert capsys.readouterr().out == ""


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["ghost", "target", " Target "])
async def test_check_server_unknown_name_is_a_tool_error(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    attempts = _record_named_scan(monkeypatch, [make_server_config(name="Target")])

    with pytest.raises(ToolError, match="not found"):
        await _build_mcp_server().call_tool("check_server", {"name": name})
    assert attempts == []


@pytest.mark.anyio
@pytest.mark.parametrize("collision", ["client", "config_path", "project_path"])
async def test_check_server_rejects_ambiguous_name_before_connecting(
    monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    first = make_server_config(name="shared")
    changes_by_collision: dict[str, dict[str, Any]] = {
        "client": {"client": ClientType.CURSOR},
        "config_path": {"config_path": "/tmp/other_config.json"},
        "project_path": {"project_path": "/synthetic/project"},
    }
    second = first.model_copy(update=changes_by_collision[collision])
    attempts = _record_named_scan(monkeypatch, [first, second])

    with pytest.raises(ToolError, match="ambiguous") as excinfo:
        await _build_mcp_server().call_tool("check_server", {"name": "shared"})
    assert attempts == []
    assert first.command is not None
    assert first.command not in str(excinfo.value)
    assert first.config_path not in str(excinfo.value)


@pytest.mark.anyio
@pytest.mark.parametrize("visible_match", [False, True])
async def test_check_server_rejects_incomplete_discovery_before_connecting(
    monkeypatch: pytest.MonkeyPatch, visible_match: bool
) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    errors = [ConfigParseError("/tmp/broken.json", ClientType.CURSOR, "SENSITIVE_CANARY")]
    servers = [make_server_config(name="target")] if visible_match else []
    attempts = _record_named_scan(monkeypatch, servers, parse_errors=errors)

    with pytest.raises(ToolError, match="discovery is incomplete") as excinfo:
        await _build_mcp_server().call_tool("check_server", {"name": "target"})
    assert attempts == []
    assert "SENSITIVE_CANARY" not in str(excinfo.value)


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["failed", "timeout"])
async def test_check_server_preserves_selected_connection_failure(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    target = make_server_config(name="target")
    attempts = _record_named_scan(
        monkeypatch,
        [target, make_server_config(name="other")],
        audit_for=lambda server: ServerAudit(
            server=server, connection_status=status, connection_error="synthetic"
        ),
    )

    payload = _tool_json(await _build_mcp_server().call_tool("check_server", {"name": "target"}))
    assert attempts == [target]
    assert payload["connection_status"] == status
    assert payload["connection_error"] == "synthetic"


@pytest.mark.anyio
async def test_check_server_keeps_user_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    target = make_server_config(name="target")
    overrides = OverrideConfig(
        overrides=[
            ServerToolOverride(server="target", tool="plain", permissions=PermissionOverride(file_read=True))
        ]
    )
    attempts = _record_named_scan(
        monkeypatch,
        [target],
        audit_for=lambda server: ServerAudit(
            server=server, connection_status="connected", tools=[make_tool("plain")]
        ),
        overrides=overrides,
    )

    payload = _tool_json(await _build_mcp_server().call_tool("check_server", {"name": "target"}))
    assert attempts == [target]
    assert any(
        finding["category"] == "file_read" and finding["source_trust"] == "operator_override"
        for finding in payload["permissions"]
    )


@pytest.mark.anyio
async def test_list_discovered_servers_lists_configs(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.server as server_module

    monkeypatch.setattr(server_module, "discover_all_configs", lambda clients: [make_server_config(name="a")])

    app = _build_mcp_server()
    payload = _tool_json(await app.call_tool("list_discovered_servers", {}))

    assert payload == [{"name": "a", "client": "claude_code", "transport": "stdio"}]
