"""Project inventory must not execute checkout code without the explicit opt-in."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import sys
import types
import zlib
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit import cli, engine, overrides, pinning, scan_cli, watcher
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import discover_all_configs
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ClientType, ConnectionMode, ServerAudit, ServerConfig, TransportType
from mcp_audit.server import _build_mcp_server

FIXTURE = Path(__file__).parent / "fixtures" / "project_scope_server.py"


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(checkout)
    monkeypatch.setattr(scan_cli, "DEFAULT_OVERRIDE_PATH", home / "overrides.yaml")
    real_load = overrides.load_override_config
    monkeypatch.setattr(
        overrides, "load_override_config", lambda path=home / "overrides.yaml": real_load(path)
    )

    class IsolatedPinStore(pinning.PinStore):
        def __init__(self, path: Path = home / "pins.yaml") -> None:
            super().__init__(path)

    monkeypatch.setattr(pinning, "PinStore", IsolatedPinStore)
    return checkout


def _entry(sentinel: Path) -> dict[str, object]:
    return {"command": sys.executable, "args": ["-I", str(FIXTURE), str(sentinel)]}


def _write_config(path: Path, sentinel: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {"fixture": _entry(sentinel)}}))


def _clone_fixture(root: Path, config: bytes) -> Path:
    """Build a tiny synthetic Git source without mutating this worktree's refs."""
    source = root / "source.git"
    (source / "objects").mkdir(parents=True)
    (source / "refs" / "heads").mkdir(parents=True)

    def git_object(kind: str, data: bytes) -> str:
        payload = f"{kind} {len(data)}\0".encode() + data
        digest = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        directory = source / "objects" / digest[:2]
        directory.mkdir(exist_ok=True)
        (directory / digest[2:]).write_bytes(zlib.compress(payload))
        return digest

    blob = git_object("blob", config)
    tree = git_object("tree", b"100644 .mcp.json\0" + bytes.fromhex(blob))
    commit = git_object(
        "commit",
        (
            f"tree {tree}\n"
            "author Fixture <fixture@example.invalid> 0 +0000\n"
            "committer Fixture <fixture@example.invalid> 0 +0000\n\n"
            "Synthetic project config\n"
        ).encode(),
    )
    (source / "HEAD").write_text("ref: refs/heads/main\n")
    (source / "refs" / "heads" / "main").write_text(commit + "\n")
    (source / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = true\n")
    clone = root / "clone"
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", str(source), str(clone)],
        check=True,
        capture_output=True,
    )
    return clone


def test_cloned_project_scan_never_spawns(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = workspace / "spawned"
    clone = _clone_fixture(workspace, json.dumps({"mcpServers": {"fixture": _entry(sentinel)}}).encode())
    monkeypatch.chdir(clone)
    result = CliRunner().invoke(cli.main, ["scan", "--json", "report.json", "--override-config", "/dev/null"])
    assert result.exit_code == 0, result.output
    assert not sentinel.exists()
    report = json.loads((clone / "report.json").read_text())
    assert report["servers_discovered"] == 1
    assert report["connection_mode"] == "skipped"
    assert report["audits"][0]["server"]["scope"] == "project"
    assert report["audits"][0]["connection_status"] == "skipped"
    assert report["warnings"][0]["code"] == "project_config_not_connected"
    assert shlex.join([sys.executable, "-I", str(FIXTURE), str(sentinel)]) in report["warnings"][0]["message"]
    assert "not connected" in result.output


@pytest.mark.parametrize("relative", [".mcp.json", ".vscode/mcp.json", ".vscode/nested/../mcp.json"])
@pytest.mark.parametrize("opt_in,skip", [(False, False), (True, False), (True, True)])
def test_scan_flag_and_explicit_project_config(
    workspace: Path, relative: str, opt_in: bool, skip: bool
) -> None:
    sentinel = workspace / "spawned"
    _write_config(workspace / relative, sentinel)
    flags = ["--connect-project-configs"] if opt_in else []
    if skip:
        flags.append("--skip-connect")
    result = CliRunner().invoke(
        cli.main,
        ["scan", "--config", relative, "--config-only", "--override-config", "/dev/null", *flags],
    )
    assert result.exit_code == 0, result.output
    assert sentinel.exists() is (opt_in and not skip)


@pytest.mark.anyio
async def test_workstation_connects_while_project_is_inventoried(workspace: Path) -> None:
    home_sentinel = workspace / "home-spawned"
    project_sentinel = workspace / "project-spawned"
    _write_config(Path.home() / ".claude.json", home_sentinel)
    _write_config(workspace / ".mcp.json", project_sentinel)
    report = await run_scan(ScanOptions(clients=[ClientType.CLAUDE_CODE]))
    assert home_sentinel.exists()
    assert not project_sentinel.exists()
    assert report.connection_mode is ConnectionMode.ATTEMPTED
    assert report.servers_connected == 1
    assert [a.server.scope for a in report.audits] == ["workstation", "project"]
    assert [a.connection_status for a in report.audits] == ["connected", "skipped"]


def test_discovery_scope_and_existing_project_path(workspace: Path) -> None:
    _write_config(workspace / ".mcp.json", workspace / "unused")
    _write_config(workspace / ".vscode/mcp.json", workspace / "unused")
    _write_config(Path.home() / ".vscode/mcp.json", workspace / "unused")
    (Path.home() / ".claude.json").write_text(
        json.dumps({"projects": {str(workspace): {"mcpServers": {"nested": _entry(workspace / "unused")}}}})
    )
    servers = discover_all_configs([ClientType.CLAUDE_CODE, ClientType.VSCODE])
    assert [s.scope for s in servers] == ["project", "project", "project", "workstation"]
    assert servers[0].project_path == str(workspace)
    assert servers[1].project_path is None  # Existing field semantics stay intact.


@pytest.mark.anyio
async def test_skipped_permissions_and_warning_redaction(workspace: Path) -> None:
    server = ServerConfig(
        name="project",
        client=ClientType.CLAUDE_CODE,
        config_path=str(workspace / ".mcp.json"),
        scope="project",
        command="npx",
        args=["server-filesystem", "a spaced directory", "--api-key", "synthetic-credential"],
        env_keys=["API_KEY"],
    )
    report = await run_scan(servers=[server])
    assert report.audits[0].permissions
    assert report.audits[0].risk_score is not None
    warning = report.warnings[0]
    assert warning.servers == ["project"]
    assert warning.check == "connection"
    assert "'a spaced directory'" in warning.message
    assert "synthetic-credential" not in warning.message
    assert "<redacted>" in warning.message
    assert report.schema_version == 1


@pytest.mark.anyio
@pytest.mark.parametrize("transport", [TransportType.HTTP, TransportType.SSE])
async def test_project_endpoints_and_canary_cannot_bypass_guard(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, transport: TransportType
) -> None:
    async def unexpected_connect(
        self: ServerConnector, config: ServerConfig, **kwargs: object
    ) -> ServerAudit:
        pytest.fail("Project connection was attempted")

    monkeypatch.setattr(ServerConnector, "connect", unexpected_connect)
    server = ServerConfig(
        name="remote",
        client=ClientType.CLAUDE_CODE,
        config_path="synthetic",
        project_path=str(workspace),
        transport=transport,
        url="https://example.invalid/mcp?api_key=synthetic-credential",
    )
    assert server.scope == "project"
    report = await run_scan(ScanOptions(canary_check=True), servers=[server])
    assert report.audits[0].connection_status == "skipped"
    assert report.audits[0].canary is None
    assert "synthetic-credential" not in report.warnings[0].message


@pytest.mark.parametrize("action", [[], ["--refresh", "fixture"], ["--refresh", "fixture", "--apply"]])
def test_pin_and_refresh_skip_project(workspace: Path, action: list[str]) -> None:
    sentinel = workspace / "spawned"
    _write_config(workspace / ".mcp.json", sentinel)
    pin_file = workspace / "pins.yaml"
    result = CliRunner().invoke(cli.main, ["pin", "--pin-file", str(pin_file), *action])
    assert result.exit_code == 0, result.output
    assert not sentinel.exists()
    assert not pin_file.exists()
    assert "not connected" in result.output


@pytest.mark.anyio
async def test_every_serve_tool_skips_project(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = workspace / "spawned"
    _write_config(workspace / ".mcp.json", sentinel)

    async def unexpected_connect(self: ServerConnector, config: ServerConfig) -> ServerAudit:
        pytest.fail("Serve attempted a project connection")

    monkeypatch.setattr(ServerConnector, "connect", unexpected_connect)
    app = _build_mcp_server()
    for tool in await app.list_tools():
        args = {"name": "fixture"} if tool.name == "check_server" else {}
        result = await app.call_tool(tool.name, args)
        assert not result.is_error, tool.name
        assert not sentinel.exists(), tool.name


@pytest.mark.parametrize("opt_in,skip", [(False, False), (True, False), (True, True)])
def test_watch_initial_and_rescan_apply_same_scope_rule(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, opt_in: bool, skip: bool
) -> None:
    sentinel = workspace / "spawned"
    _write_config(workspace / ".mcp.json", sentinel)
    reports = []
    real_scan = engine.run_scan

    async def record_scan(options: ScanOptions, **kwargs: object) -> object:
        report = await real_scan(options)
        reports.append(report)
        return report

    async def changes(*paths: str) -> AsyncIterator[set[tuple[int, str]]]:
        yield {(2, str(workspace / ".mcp.json"))}

    monkeypatch.setitem(sys.modules, "watchfiles", types.SimpleNamespace(awatch=changes))
    monkeypatch.setattr(engine, "run_scan", record_scan)
    flags = ["--connect-project-configs"] if opt_in else []
    if skip:
        flags.append("--skip-connect")
    result = CliRunner().invoke(watcher.watch_command, ["--override-config", "/dev/null", *flags])
    assert result.exit_code == 0, result.output
    assert len(reports) == 2
    assert sentinel.exists() is (opt_in and not skip)
    expected = "connected" if opt_in and not skip else "skipped"
    assert all(report.audits[0].connection_status == expected for report in reports)
