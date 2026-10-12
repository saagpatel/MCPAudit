"""Fleet CLI acceptance using synthetic configs and local fixture servers only."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
from collections.abc import Callable
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner

from mcp_audit import check_cli, cli, fleet_workers
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import _ScanContext
from mcp_audit.models import ClientType, ServerAudit, ServerConfig
from mcp_audit.review_discovery import ReviewSources, review_sources

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    monkeypatch.delenv("_MCP_AUDIT_SHARDING", raising=False)
    monkeypatch.chdir(tmp_path)


def _config(path: Path, names: tuple[str, ...], *, canary: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = "deadbugz_server.py" if canary else "mock_server.py"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    name: {
                        "command": sys.executable,
                        "args": [str(FIXTURES / fixture), *(["stable"] if canary else [])],
                    }
                    for name in names
                }
            }
        )
    )
    return path


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--connect"], "--connect-all cannot be combined with --connect or --server"),
        (["--server", "claude_code:workstation:fixture"], "--connect-all cannot be combined"),
        (["--skip-connect"], "--skip-connect cannot be combined"),
        (["--canary-check"], "--canary-check requires --config FILE"),
        (["--canary-check", "--config", "fixture.json", "--include-discovered"], "without discovery"),
        (["--max-concurrency", "0"], "Invalid value for '--max-concurrency'"),
    ],
)
def test_invalid_fleet_options_fail_before_discovery(
    args: list[str], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid options must fail before discovery or connections")

    monkeypatch.setattr(check_cli, "review_sources", forbidden)
    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    result = CliRunner().invoke(cli.main, ["check", "--connect-all", *args])
    assert result.exit_code == 2, result.output
    assert message in result.stderr


@pytest.mark.parametrize("config_only", [False, True])
def test_explicit_fleet_connects_all_local_fixtures_without_discovery(
    config_only: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unrelated discovered fixture must never be read by an explicit-only check.
    _config(Path.home() / ".cursor/mcp.json", ("unselected",))
    config = _config(tmp_path / "fleet.json", ("first", "second"))

    def explicit_only(
        config: Path | None, include_discovered: bool, project: Path | None, clients: tuple[ClientType, ...]
    ) -> ReviewSources:
        assert config is not None and not include_discovered
        return review_sources(config, include_discovered, project, clients)

    monkeypatch.setattr(check_cli, "review_sources", explicit_only)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect-all",
            "--timeout",
            "15",
            "--json",
            *(["--config-only"] if config_only else []),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_discovered"] == report["servers_connected"] == 2
    assert report["connection_mode"] == "attempted"
    assert [audit["server"]["name"] for audit in report["audits"]] == ["first", "second"]
    assert all(audit["tools"] for audit in report["audits"])
    assert "Configured code may execute" in result.stderr


@pytest.mark.parametrize("project_opt_in", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
def test_fleet_project_guard_keeps_skipped_audits_and_requires_opt_in(
    project_opt_in: bool, explicit: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # .mcp.json is project-scope even when selected explicitly.
    project_config = _config(tmp_path / ".mcp.json", ("project-fixture",))
    if not explicit:
        _config(Path.home() / ".claude.json", ("workstation-fixture",))
    connected: list[str] = []
    original = ServerConnector.connect

    async def recording(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        connected.append(server.name)
        return await original(self, server)

    monkeypatch.setattr(ServerConnector, "connect", recording)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--connect-all",
            "--timeout",
            "15",
            "--override-config",
            os.devnull,
            "--json",
            *(["--config", str(project_config)] if explicit else ["--client", "claude-code"]),
            *(["--connect-project-configs"] if project_opt_in else []),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_discovered"] == (1 if explicit else 2)
    assert report["servers_connected"] == int(not explicit) + int(project_opt_in)
    project = next(a for a in report["audits"] if a["server"]["scope"] == "project")
    assert project["connection_status"] == ("connected" if project_opt_in else "skipped")
    assert ("project-fixture" in connected) is project_opt_in
    warnings = [w for w in report["warnings"] if w["code"] == "project_config_not_connected"]
    assert bool(warnings) is not project_opt_in
    assert report["connection_mode"] == ("skipped" if explicit and not project_opt_in else "attempted")


def test_include_discovered_adds_workstation_fixtures_to_explicit_fleet(tmp_path: Path) -> None:
    config = _config(tmp_path / "fleet.json", ("explicit",))
    _config(Path.home() / ".cursor/mcp.json", ("discovered",))
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--include-discovered",
            "--client",
            "cursor",
            "--connect-all",
            "--override-config",
            os.devnull,
            "--timeout",
            "15",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_connected"] == 2
    assert {a["server"]["name"] for a in report["audits"]} == {"explicit", "discovered"}


def test_explicit_fleet_canary_exercises_each_local_fixture(tmp_path: Path) -> None:
    config = _config(tmp_path / "fleet.json", ("first", "second"), canary=True)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect-all",
            "--canary-check",
            "--canary-calls",
            "2",
            "--canary-identities",
            "1",
            "--max-concurrency",
            "1",
            "--timeout",
            "15",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_connected"] == 2
    assert all(a["canary"]["completed_calls"] == 2 for a in report["audits"])
    assert all(a["canary"]["status"] == "complete" for a in report["audits"])


def test_fleet_concurrency_limits_sessions_and_preserves_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path / "fleet.json", tuple(str(i) for i in range(5)))
    active = peak = 0
    completed: list[str] = []

    async def connected(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        nonlocal active, peak
        assert self.timeout == 7
        active += 1
        peak = max(peak, active)
        try:
            await anyio.sleep((5 - int(server.name)) * 0.005)
            completed.append(server.name)
            return ServerAudit(server=server, connection_status="connected")
        finally:
            active -= 1

    monkeypatch.setattr(ServerConnector, "connect", connected)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect-all",
            "--timeout",
            "7",
            "--max-concurrency",
            "2",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert peak == 2
    assert completed != [str(i) for i in range(5)]
    assert [a["server"]["name"] for a in json.loads(result.stdout)["audits"]] == [str(i) for i in range(5)]


def test_fleet_timeout_is_per_session_and_excludes_queue_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path / "fleet.json", ("timeout", "queued"))
    entered: list[str] = []

    async def connected(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        assert self.timeout == 1
        entered.append(server.name)
        with anyio.move_on_after(self.timeout) as scope:
            await anyio.sleep(2 if server.name == "timeout" else 0.05)
        return ServerAudit(server=server, connection_status="timeout" if scope.cancel_called else "connected")

    monkeypatch.setattr(ServerConnector, "connect", connected)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect-all",
            "--timeout",
            "1",
            "--max-concurrency",
            "1",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert entered == ["timeout", "queued"]
    assert [a["connection_status"] for a in json.loads(result.stdout)["audits"]] == ["timeout", "connected"]


@pytest.mark.skipif(os.name != "posix", reason="CLI sharding requires POSIX spawn")
def test_fleet_cli_shards_local_fixtures_with_json_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path / "fleet.json", ("first", "second"))
    monkeypatch.setattr(os, "cpu_count", lambda: 2)
    sharded: list[int] = []
    original = fleet_workers.run_sharded

    async def recording(context: _ScanContext, workers: int, advance: Callable[[], None]) -> None:
        sharded.append(workers)
        assert context.opts.max_concurrency == 1
        assert context.opts.timeout == 15
        await original(context, workers, advance)

    monkeypatch.setattr(fleet_workers, "run_sharded", recording)
    reports = []
    for mode in ("off", "on"):
        monkeypatch.setenv("_MCP_AUDIT_SHARDING", mode)
        result = CliRunner().invoke(
            cli.main,
            [
                "check",
                "--config",
                str(config),
                "--connect-all",
                "--timeout",
                "15",
                "--max-concurrency",
                "1",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)
        report.pop("scan_timestamp")
        report.pop("scan_duration_seconds")
        reports.append(report)
    assert sharded == [2]
    assert reports[0] == reports[1]
    assert reports[1]["servers_connected"] == 2
    assert mp.active_children() == []


@pytest.mark.skipif(os.name != "posix", reason="CLI sharding requires POSIX spawn")
def test_large_fleet_cli_enables_automatic_sharding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path / "fleet.json", tuple(f"srv-{i:04d}" for i in range(257)))
    monkeypatch.setattr(os, "cpu_count", lambda: 2)
    sharded: list[int] = []

    async def bounded_shard(context: _ScanContext, workers: int, advance: Callable[[], None]) -> None:
        sharded.append(workers)
        # Prove CLI threshold dispatch without launching 257 fixture processes.
        for index, server in enumerate(context.servers):
            context.audits[index] = ServerAudit(server=server, connection_status="connected")
            advance()

    monkeypatch.setattr(fleet_workers, "run_sharded", bounded_shard)
    result = CliRunner().invoke(cli.main, ["check", "--config", str(config), "--connect-all", "--json"])
    assert result.exit_code == 0, result.output
    assert sharded == [2]
    assert json.loads(result.stdout)["servers_connected"] == 257
