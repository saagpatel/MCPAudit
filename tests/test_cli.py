"""Tests for CLI orchestration helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner

from mcp_audit import cli
from mcp_audit.models import AuditReport, ServerAudit, TransportType
from mcp_audit.overrides import OverrideApplier, OverrideConfig
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
    assert "1.5.4" in result.output


def test_scan_config_only_requires_config() -> None:
    result = CliRunner().invoke(cli.main, ["scan", "--config-only"])

    assert result.exit_code != 0
    assert "--config-only requires --config PATH" in result.output


def test_discover_reports_duplicate_server_names(monkeypatch: pytest.MonkeyPatch) -> None:
    first_server = make_server_config(name="srv")
    second_server = first_server.model_copy(update={"config_path": "/tmp/other_config.json"})
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [first_server, second_server])

    result = CliRunner().invoke(cli.main, ["discover"])

    assert result.exit_code == 0
    assert "Config health warnings found" in result.output
    assert "'srv' appears 2 times" in result.output
    assert "pins are keyed by server name" in result.output


def test_discover_reports_config_health_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_command = make_server_config(name="missing-command", command=None)
    missing_binary = make_server_config(name="missing-binary", command="/definitely/missing/mcp-server")
    sse_server = make_server_config(
        name="legacy-sse",
        command=None,
        transport=TransportType.SSE,
        url="https://example.com/sse",
    )
    shell_server = make_server_config(name="shell-server", command="bash", args=["-lc", "echo hi"])
    remote_arg_server = make_server_config(
        name="remote-arg",
        command="node",
        args=["https://example.com/bootstrap.js"],
    )
    package_runner_server = make_server_config(
        name="package-runner",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
    )
    docker_runner_server = make_server_config(
        name="docker-runner",
        command="docker",
        args=["run", "--rm", "ghcr.io/example/mcp-server:latest"],
    )
    credential_server = make_server_config(
        name="credential-heavy",
        env_keys=["TOKEN", "SECRET"],
    ).model_copy(update={"headers_keys": ["Authorization"]})
    monkeypatch.setattr(
        cli,
        "discover_all_configs",
        lambda clients: [
            missing_command,
            missing_binary,
            sse_server,
            shell_server,
            remote_arg_server,
            package_runner_server,
            docker_runner_server,
            credential_server,
        ],
    )

    result = CliRunner().invoke(cli.main, ["discover"])

    assert result.exit_code == 0
    assert "Config health warnings found" in result.output
    assert "'missing-command' uses stdio but has no command" in result.output
    assert "'missing-binary' command path does not exist locally" in result.output
    assert "'legacy-sse' uses deprecated SSE transport" in result.output
    assert "'legacy-sse' declares a remote endpoint" in result.output
    assert "'shell-server' launches through shell wrapper 'bash'" in result.output
    assert "'remote-arg' command or args include a remote URL" in result.output
    assert "'package-runner' launches through package runner 'npx'" in result.output
    assert "'docker-runner' launches through package runner 'docker'" in result.output
    assert "'credential-heavy' references 3 credential key names" in result.output


def test_discover_reports_global_project_scope_conflicts(monkeypatch: pytest.MonkeyPatch) -> None:
    global_server = make_server_config(name="github")
    project_server = global_server.model_copy(
        update={
            "config_path": "/repo/.mcp.json",
            "project_path": "/repo",
        }
    )
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [global_server, project_server])

    result = CliRunner().invoke(cli.main, ["discover"])

    assert result.exit_code == 0
    assert "'github' appears 2 times" in result.output
    assert "'github' is configured in both global and project scopes" in result.output


def test_discover_reports_conflicting_server_definitions(monkeypatch: pytest.MonkeyPatch) -> None:
    npx_server = make_server_config(
        name="search",
        command="npx",
        args=["-y", "@example/search-server"],
    )
    uvx_server = make_server_config(
        name="search",
        command="uvx",
        args=["--from", "example-search-mcp", "search-mcp"],
    ).model_copy(update={"config_path": "/tmp/other_config.json"})
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [npx_server, uvx_server])

    result = CliRunner().invoke(cli.main, ["discover"])

    assert result.exit_code == 0
    assert "'search' has multiple command or URL definitions" in result.output
    assert "'search' launches through package runner 'npx'" in result.output
    assert "'search' launches through package runner 'uvx'" in result.output


def test_run_scan_core_config_only_ignores_discovered_configs(monkeypatch: pytest.MonkeyPatch) -> None:
    discovered = make_server_config(name="discovered")
    custom = make_server_config(name="custom")

    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [discovered])
    monkeypatch.setattr(cli, "_parse_extra_config", lambda path: [custom])

    report = anyio.run(
        cli._run_scan_core,
        True,
        None,
        10,
        "custom.json",
        OverrideApplier(OverrideConfig()),
        False,
        False,
        False,
        True,
    )

    assert [audit.server.name for audit in report.audits] == ["custom"]


def test_run_scan_core_reports_structured_config_health(monkeypatch: pytest.MonkeyPatch) -> None:
    first_server = make_server_config(name="srv")
    second_server = first_server.model_copy(update={"config_path": "/tmp/other_config.json"})

    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [first_server, second_server])

    report = anyio.run(
        cli._run_scan_core,
        True,
        None,
        10,
        None,
        OverrideApplier(OverrideConfig()),
    )

    assert [finding.finding_type for finding in report.config_health_findings] == ["duplicate_server_name"]
    assert report.config_health_findings[0].server_name == "srv"
    assert report.config_health_findings[0].severity == "medium"


def test_scan_reports_duplicate_server_names(monkeypatch: pytest.MonkeyPatch) -> None:
    first_server = make_server_config(name="srv")
    second_server = first_server.model_copy(update={"config_path": "/tmp/other_config.json"})
    audits = [
        ServerAudit(server=first_server, connection_status="skipped"),
        ServerAudit(server=second_server, connection_status="skipped"),
    ]
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [first_server, second_server])

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report(audits)

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)

    result = CliRunner().invoke(cli.main, ["scan", "--skip-connect"])

    assert result.exit_code == 0
    assert "Config health warnings found" in result.output
    assert "'srv' appears 2 times" in result.output


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


def test_run_pin_skips_duplicate_server_names_without_writing(monkeypatch: object, tmp_path: Path) -> None:
    store = PinStore(path=tmp_path / "pins.yaml")
    first_server = make_server_config(name="srv")
    second_server = first_server.model_copy(update={"config_path": "/tmp/other_config.json"})
    audits = [
        ServerAudit(
            server=first_server,
            connection_status="connected",
            tools=[make_tool("read_file")],
        ),
        ServerAudit(
            server=second_server,
            connection_status="connected",
            tools=[make_tool("write_file")],
        ),
    ]

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report(audits)

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    anyio.run(cli._run_pin, None, store)

    assert store.tool_count("srv") == 0


def test_run_pin_refresh_reviews_drift_without_writing(monkeypatch: object, tmp_path: Path) -> None:
    store = PinStore(path=tmp_path / "pins.yaml")
    store.pin_server("srv", [make_tool("read_file", description="v1")])
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("read_file", description="v2")],
    )

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    anyio.run(cli._run_pin_refresh, "srv", store, False)

    findings = PinStore(path=tmp_path / "pins.yaml").check_drift("srv", audit.tools)
    assert len(findings) == 1
    assert findings[0].tool_name == "read_file"


def test_run_pin_refresh_applies_reviewed_baseline(monkeypatch: object, tmp_path: Path) -> None:
    store = PinStore(path=tmp_path / "pins.yaml")
    store.pin_server("srv", [make_tool("read_file", description="v1")])
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("read_file", description="v2")],
    )

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    anyio.run(cli._run_pin_refresh, "srv", store, True)

    findings = PinStore(path=tmp_path / "pins.yaml").check_drift("srv", audit.tools)
    assert findings == []


def test_pin_refresh_requires_apply_to_write(monkeypatch: object, tmp_path: Path) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("srv", [make_tool("read_file", description="v1")])
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("read_file", description="v2")],
    )

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    result = CliRunner().invoke(cli.main, ["pin", "--refresh", "srv", "--pin-file", str(pin_file)])

    assert result.exit_code == 0
    assert "Review complete; no pins were changed" in result.output
    assert PinStore(path=pin_file).check_drift("srv", audit.tools)


def test_pin_refresh_json_reports_drift_without_writing(monkeypatch: object, tmp_path: Path) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("srv", [make_tool("read_file", description="v1")])
    audit = ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("read_file", description="v2")],
    )

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report([audit])

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    result = CliRunner().invoke(
        cli.main,
        ["pin", "--refresh", "srv", "--json", "--pin-file", str(pin_file)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["server"] == "srv"
    assert payload["current_tool_count"] == 1
    assert payload["applied"] is False
    assert payload["drift_counts"]["changed"] == 1
    assert payload["drift"][0]["tool_name"] == "read_file"
    assert PinStore(path=pin_file).check_drift("srv", audit.tools)


def test_pin_refresh_json_reports_duplicate_server_name_without_writing(
    monkeypatch: object, tmp_path: Path
) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("srv", [make_tool("read_file", description="v1")])
    first_server = make_server_config(name="srv")
    second_server = first_server.model_copy(update={"config_path": "/tmp/other_config.json"})
    audits = [
        ServerAudit(
            server=first_server,
            connection_status="connected",
            tools=[make_tool("read_file", description="v2")],
        ),
        ServerAudit(
            server=second_server,
            connection_status="connected",
            tools=[make_tool("write_file")],
        ),
    ]

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _report(audits)

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)  # type: ignore[attr-defined]

    result = CliRunner().invoke(
        cli.main,
        ["pin", "--refresh", "srv", "--json", "--apply", "--pin-file", str(pin_file)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["server"] == "srv"
    assert payload["current_tool_count"] == 0
    assert payload["applied"] is False
    assert "multiple discovered MCP configs" in payload["error"]
    assert PinStore(path=pin_file).check_drift("srv", [make_tool("read_file", description="v2")])


def test_pin_rejects_apply_without_refresh() -> None:
    result = CliRunner().invoke(cli.main, ["pin", "--apply"])

    assert result.exit_code == 1
    assert "--apply can only be used with --refresh or --clear-stale" in result.output


def test_pin_clear_removes_intentionally_removed_server(tmp_path: Path) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("removed-server", [make_tool("read_file")])
    store.pin_server("kept-server", [make_tool("write_file")])

    result = CliRunner().invoke(
        cli.main,
        ["pin", "--clear", "removed-server", "--pin-file", str(pin_file)],
    )

    assert result.exit_code == 0
    refreshed = PinStore(path=pin_file)
    assert refreshed.tool_count("removed-server") == 0
    assert refreshed.tool_count("kept-server") == 1


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


def test_pin_stale_reports_removed_server_without_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("configured", [make_tool("read_file")])
    store.pin_server("removed", [make_tool("write_file")])
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [make_server_config(name="configured")])

    result = CliRunner().invoke(cli.main, ["pin", "--stale", "--pin-file", str(pin_file)])

    assert result.exit_code == 0
    assert "Stale pin baselines:" in result.output
    assert "removed" in result.output
    assert "Review only; no pins were changed" in result.output
    refreshed = PinStore(path=pin_file)
    assert refreshed.tool_count("removed") == 1


def test_pin_stale_json_reports_removed_server_without_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("configured", [make_tool("read_file")])
    store.pin_server("removed", [make_tool("write_file")])
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [make_server_config(name="configured")])

    result = CliRunner().invoke(cli.main, ["pin", "--stale", "--json", "--pin-file", str(pin_file)])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["stale_server_count"] == 1
    assert payload["stale_servers"][0]["name"] == "removed"
    assert "pin --clear" in payload["stale_servers"][0]["remediation"]
    refreshed = PinStore(path=pin_file)
    assert refreshed.tool_count("removed") == 1


def test_pin_clear_stale_reviews_removed_servers_without_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("configured", [make_tool("read_file")])
    store.pin_server("removed-a", [make_tool("write_file")])
    store.pin_server("removed-b", [make_tool("delete_file")])
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [make_server_config(name="configured")])

    result = CliRunner().invoke(cli.main, ["pin", "--clear-stale", "--pin-file", str(pin_file)])

    assert result.exit_code == 0
    assert "Stale pin cleanup review:" in result.output
    assert "removed-a" in result.output
    assert "removed-b" in result.output
    assert "no pins were changed" in result.output
    refreshed = PinStore(path=pin_file)
    assert refreshed.tool_count("configured") == 1
    assert refreshed.tool_count("removed-a") == 1
    assert refreshed.tool_count("removed-b") == 1


def test_pin_clear_stale_json_applies_reviewed_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(path=pin_file)
    store.pin_server("configured", [make_tool("read_file")])
    store.pin_server("removed-a", [make_tool("write_file")])
    store.pin_server("removed-b", [make_tool("delete_file")])
    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [make_server_config(name="configured")])

    result = CliRunner().invoke(
        cli.main,
        ["pin", "--clear-stale", "--json", "--apply", "--pin-file", str(pin_file)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["applied"] is True
    assert payload["stale_server_count"] == 2
    assert payload["removed_server_count"] == 2
    assert payload["removed_servers"] == ["removed-a", "removed-b"]
    refreshed = PinStore(path=pin_file)
    assert refreshed.tool_count("configured") == 1
    assert refreshed.tool_count("removed-a") == 0
    assert refreshed.tool_count("removed-b") == 0
