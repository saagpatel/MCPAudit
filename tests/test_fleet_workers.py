"""Spawn-boundary parity, degraded workers, global budgets and owned cleanup."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import signal
import struct
import subprocess
import time
from multiprocessing.connection import Connection
from pathlib import Path
from typing import cast

import anyio
import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_audit import engine, fleet_workers
from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, _ScanContext, _WorkerSetup
from mcp_audit.models import AuditReport, ServerAudit, ServerConfig
from mcp_audit.overrides import OverrideApplier, OverrideConfig, PermissionOverride, ServerToolOverride
from mcp_audit.pinning import PinStore
from mcp_audit.stdio_transport import _GROUP_OBSERVER
from tests.conftest import make_server_config
from tests.test_transport_hygiene import _assert_process_group_exited, _stdio_server

FIXTURES = Path(__file__).parent / "fixtures"


def _context(count: int, options: ScanOptions | None = None) -> _ScanContext:
    return engine._prepare_scan(
        options or ScanOptions(skip_connect=True),
        [make_server_config(name=f"srv-{index:04d}") for index in range(count)],
        [],
        OverrideApplier(OverrideConfig()),
        Console(quiet=True),
        time.monotonic(),
    )


@pytest.mark.parametrize(
    ("servers", "cpus", "expected"),
    [(256, 8, 0), (257, 8, 2), (500, 16, 2), (2000, 16, 8), (4096, 4, 4), (257, 1, 0), (257, None, 0)],
)
def test_threshold_and_worker_count(
    servers: int, cpus: int | None, expected: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("_MCP_AUDIT_SHARDING", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: cpus)
    assert fleet_workers.worker_count(_context(servers)) == expected


@pytest.mark.parametrize(
    "options",
    [
        ScanOptions(canary_check=True),
        ScanOptions(llm_analysis=True),
        ScanOptions(pin_check=True),
        ScanOptions(escalation_check=True),
        ScanOptions(provenance_check=True),
        ScanOptions(integrity_check=True),
        ScanOptions(verify_artifacts=True),
        ScanOptions(download_artifacts=True),
    ],
)
def test_unsafe_options_fall_back_without_warning(
    options: ScanOptions, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    context = _context(257)
    context.opts = options
    assert fleet_workers.worker_count(context) == 0
    assert context.scan_warnings == []


def test_unsupported_spawn_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(257)
    monkeypatch.setattr(mp, "get_all_start_methods", lambda: ["fork"])
    assert fleet_workers.worker_count(context) == 0


def test_caller_pin_store_custom_applier_and_forced_single_core_fall_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(257)
    context.pin_store = PinStore(path=tmp_path / "pins.yaml", record_verification=False)
    assert fleet_workers.worker_count(context) == 0
    context.pin_store = None
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    monkeypatch.setattr(os, "cpu_count", lambda: 1)
    assert fleet_workers.worker_count(context) == 0
    monkeypatch.undo()

    class CustomApplier(OverrideApplier):
        pass

    context.applier = CustomApplier(OverrideConfig())
    assert fleet_workers.worker_count(context) == 0


def _stable(report: AuditReport) -> dict[str, object]:
    data = report.model_dump(mode="json")
    del data["scan_timestamp"]
    del data["scan_duration_seconds"]
    return cast(dict[str, object], data)


@pytest.mark.anyio
async def test_large_connected_fleet_json_parity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Local stdio fixture only; project guards add warnings in non-name order.
    root = tmp_path / "peer"
    root.mkdir()
    servers = [
        _stdio_server("normal", root).model_copy(update={"name": f"srv-{256 - index:04d}"})
        for index in range(257)
    ]
    for server in servers[::7]:
        server.scope = "project"
    options = ScanOptions(
        inject_check=True,
        ssrf_check=True,
        egress_check=True,
        trifecta_check=True,
        shadow_check=True,
        max_concurrency=7,
    )
    applier = OverrideApplier(
        OverrideConfig(
            overrides=[
                ServerToolOverride(server="*", tool="status", permissions=PermissionOverride(file_read=True))
            ]
        )
    )
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "off")
    single = await engine.run_scan(options, servers=servers, override_applier=applier)
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    sharded = await engine.run_scan(options, servers=servers, override_applier=applier)
    assert _stable(single) == _stable(sharded)
    assert sharded.servers_connected == 220
    assert [audit.server.name for audit in sharded.audits] == [server.name for server in servers]
    assert mp.active_children() == []
    groups = {json.loads(path.read_text())["pgid"] for path in root.glob("server-*.json")}
    for group in groups:
        await _assert_process_group_exited(group)


def test_large_synthetic_cli_json_and_exit_code_parity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "fleet.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    f"srv-{index:04d}": {"command": "fixture-filesystem", "args": ["./synthetic"]}
                    for index in range(257)
                }
            }
        )
    )
    results = []
    reports = []
    for mode in ("off", "on"):
        monkeypatch.setenv("_MCP_AUDIT_SHARDING", mode)
        output = tmp_path / f"{mode}.json"
        results.append(
            CliRunner().invoke(
                main,
                [
                    "scan",
                    "--config",
                    str(config),
                    "--config-only",
                    "--skip-connect",
                    "--override-config",
                    os.devnull,
                    "--json",
                    str(output),
                    "--inject-check",
                    "--trifecta-check",
                    "--shadow-check",
                ],
            )
        )
        reports.append(_stable(AuditReport.model_validate_json(output.read_text())))
    assert results[0].exit_code == results[1].exit_code == 0
    assert reports[0] == reports[1]
    assert mp.active_children() == []


@pytest.mark.anyio
@pytest.mark.parametrize("refresh", [False, True])
async def test_pin_write_and_refresh_callers_disable_sharding(
    refresh: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from mcp_audit import overrides, pin_cli

    class ScanObserved(Exception):
        pass

    async def scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        assert kwargs["_allow_sharding"] is False
        raise ScanObserved

    monkeypatch.setattr(overrides, "load_override_config", lambda path: OverrideConfig())
    monkeypatch.setattr(pin_cli, "run_scan", scan)
    store = PinStore(path=tmp_path / "pins.yaml", unsigned=True)
    with pytest.raises(ScanObserved):
        if refresh:
            await pin_cli._run_pin_refresh("fixture", store, False)
        else:
            await pin_cli._run_pin(None, store)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["stderr-malformed", "spawn-child-ignore", "hang"])
async def test_sharded_stderr_timeout_and_transport_cleanup(
    mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    roots = [tmp_path / str(index) for index in range(2)]
    for root in roots:
        root.mkdir()
    report = await engine.run_scan(
        ScanOptions(timeout=1),
        servers=[
            _stdio_server(mode, root).model_copy(update={"name": str(index)})
            for index, root in enumerate(roots)
        ],
    )
    assert report.servers_failed == 2
    assert not any(warning.code == "worker_process_failed" for warning in report.warnings)
    if mode == "stderr-malformed":
        for audit in report.audits:
            assert audit.connection_error and "diagnostic marker" in audit.connection_error
            assert "synthetic-secret" not in audit.connection_error
        monkeypatch.setenv("_MCP_AUDIT_SHARDING", "off")
        single = await engine.run_scan(
            ScanOptions(timeout=1), servers=[audit.server for audit in report.audits]
        )
        assert _stable(single) == _stable(report)
    for root in roots:
        records = [json.loads(path.read_text()) for path in root.glob("*.json")]
        assert records
        for group in {record["pgid"] for record in records}:
            await _assert_process_group_exited(group)
    assert mp.active_children() == []


@pytest.mark.anyio
async def test_analysis_budget_still_applies_inside_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    report = await engine.run_scan(ScanOptions(timeout=0, skip_connect=True), servers=_context(2).servers)
    assert all(audit.connection_status == "timeout" for audit in report.audits)
    assert [warning.code for warning in report.warnings] == ["analysis_timeout", "analysis_timeout"]
    assert all(not audit.permissions for audit in report.audits)
    assert mp.active_children() == []


@pytest.mark.anyio
async def test_registration_failure_still_reaps_the_spawned_group(tmp_path: Path) -> None:
    groups: list[int] = []

    def fail_registration(pid: int, started: bool) -> None:
        groups.append(pid)
        raise BrokenPipeError("parent channel closed")

    token = _GROUP_OBSERVER.set(fail_registration)
    try:
        audit = await ServerConnector(timeout=2).connect(_stdio_server("normal", tmp_path))
    finally:
        _GROUP_OBSERVER.reset(token)
    assert audit.connection_status == "failed"
    assert len(groups) == 1
    await _assert_process_group_exited(groups[0])


def _crashing_worker(
    channel: Connection, setup: _WorkerSetup, servers: list[tuple[int, ServerConfig]], concurrency: int
) -> None:
    if servers[0][0] == 0:
        os.setsid()
        index, server = servers[0]
        channel.send(fleet_workers._Acquire(index))
        assert channel.recv() == index
        channel.send(
            fleet_workers._Result(
                index, ServerAudit(server=server, connection_status="skipped"), [], set(), {}
            )
        )
        # Simulate an abrupt death holding the fleet's only connection token.
        os.kill(os.getpid(), signal.SIGKILL)
    else:
        fleet_workers._worker_main(channel, setup, servers, concurrency)


@pytest.mark.anyio
async def test_crash_preserves_results_and_siblings_and_reclaims_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = fleet_workers._worker_main
    # Restore the true target inside the sibling, avoiding recursive dispatch.
    monkeypatch.setattr(fleet_workers, "_worker_main", _crashing_worker)
    context = _context(6, ScanOptions(max_concurrency=1))
    # No local programs needed for the surviving shard: connector rejects absent commands.
    for server in context.servers:
        server.command = None
    advances: list[int] = []
    with anyio.fail_after(10):
        await fleet_workers.run_sharded(context, 2, lambda: advances.append(1))
    monkeypatch.setattr(fleet_workers, "_worker_main", original)
    assert context.audits[0].connection_status == "skipped"
    assert all(audit.connection_status == "failed" for audit in context.audits[1:])
    missing = [warning for warning in context.scan_warnings if warning.code == "worker_process_failed"]
    assert [warning.servers for warning in missing] == [["srv-0001"], ["srv-0002"]]
    assert len(advances) == 6
    assert mp.active_children() == []


def _budget_worker(
    channel: Connection, setup: _WorkerSetup, servers: list[tuple[int, ServerConfig]], concurrency: int
) -> None:
    os.setsid()
    assert mp.get_start_method() == "spawn"
    channel.send(
        fleet_workers._Result(
            servers[0][0], ServerAudit(server=servers[0][1], connection_status="skipped"), [], set(), {}
        )
    )
    assert concurrency == 2  # ceil(5/3)
    # Send two requests before waiting: rounded local limits could otherwise open six.
    for index, _ in servers[:2]:
        channel.send(fleet_workers._Acquire(index))
    # The test parent opens this gate after granting exactly five live tokens.
    # No timing assumption is needed to saturate the broker before releasing.
    gate = Path(servers[0][1].config_path)
    while not gate.exists():
        time.sleep(0.01)
    for _ in servers[:2]:
        index = channel.recv()
        time.sleep(0.02)
        channel.send(fleet_workers._Release(index))
    for index, server in servers[1:]:
        channel.send(
            fleet_workers._Result(
                index, ServerAudit(server=server, connection_status="skipped"), [], set(), {}
            )
        )


@pytest.mark.anyio
async def test_rounded_limits_do_not_exceed_global_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(fleet_workers, "_worker_main", _budget_worker)
    context = _context(9, ScanOptions(max_concurrency=5))
    gate = tmp_path / "budget-full"
    for server in context.servers:
        server.config_path = str(gate)
    # Parent grants are observable at the exact process boundary.
    original = Connection.send
    active: set[int] = set()
    peak = 0

    def send(channel: Connection, value: object) -> None:
        nonlocal peak
        if isinstance(value, int):
            active.add(value)
            peak = max(peak, len(active))
        original(channel, value)
        if peak == 5:
            gate.touch()

    original_recv = Connection.recv

    def recv(channel: Connection) -> object:
        value: object = original_recv(channel)
        if isinstance(value, fleet_workers._Release):
            active.remove(value.index)
        return value

    monkeypatch.setattr(Connection, "send", send)
    monkeypatch.setattr(Connection, "recv", recv)
    with anyio.fail_after(10):
        await fleet_workers.run_sharded(context, 3, lambda: None)
    assert peak == 5
    assert not active
    assert not context.scan_warnings
    assert mp.active_children() == []


@pytest.mark.anyio
async def test_worker_start_failure_is_redacted_and_advances_all_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_start(process: mp.process.BaseProcess) -> None:
        raise OSError("token=synthetic-secret")

    monkeypatch.setattr(mp.process.BaseProcess, "start", fail_start)
    context = _context(4)
    advances: list[int] = []
    await fleet_workers.run_sharded(context, 2, lambda: advances.append(1))
    assert len(advances) == 4
    assert all(audit.connection_status == "failed" for audit in context.audits)
    assert [warning.code for warning in context.scan_warnings] == ["worker_process_failed"] * 4
    assert "synthetic-secret" not in json.dumps([audit.model_dump() for audit in context.audits])
    assert mp.active_children() == []


def _child_crashing_worker(
    channel: Connection, setup: _WorkerSetup, servers: list[tuple[int, ServerConfig]], concurrency: int
) -> None:
    if servers[0][0] != 0:
        fleet_workers._worker_main(channel, setup, servers, concurrency)
        return
    os.setsid()
    server = servers[0][1]
    # Local hostile fixture spawns a shutdown-resistant child in its owned group.
    process = subprocess.Popen(
        [cast(str, server.command), *server.args], start_new_session=True, stdout=subprocess.DEVNULL
    )
    channel.send(fleet_workers._Group(process.pid, True))
    root = Path(server.args[-1])
    deadline = time.monotonic() + 5
    while not list(root.glob("child-*.json")):
        if time.monotonic() > deadline:
            raise RuntimeError("fixture child did not start")
        time.sleep(0.01)
    os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.anyio
async def test_killed_worker_server_and_child_groups_are_reaped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(fleet_workers, "_worker_main", _child_crashing_worker)
    context = _context(4)
    context.servers[0] = _stdio_server("spawn-child-ignore", tmp_path)
    with anyio.fail_after(10):
        await fleet_workers.run_sharded(context, 2, lambda: None)
    for record in tmp_path.glob("*.json"):
        group = json.loads(record.read_text())["pgid"]
        await _assert_process_group_exited(group)
    assert list(tmp_path.glob("child-*.json"))
    assert mp.active_children() == []


def _partial_frame_worker(
    channel: Connection, setup: _WorkerSetup, servers: list[tuple[int, ServerConfig]], concurrency: int
) -> None:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(channel.fileno(), struct.pack("!i", 100) + b"partial")
    time.sleep(60)


@pytest.mark.anyio
async def test_parent_timeout_is_not_blocked_by_partial_worker_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fleet_workers, "_worker_main", _partial_frame_worker)
    started = time.monotonic()
    with anyio.move_on_after(0.5) as timeout:
        await fleet_workers.run_sharded(_context(2), 2, lambda: None)
    assert timeout.cancel_called
    assert time.monotonic() - started < 5
    assert mp.active_children() == []


@pytest.mark.anyio
async def test_parent_cancellation_reaps_workers_and_server_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("_MCP_AUDIT_SHARDING", "on")
    roots = [tmp_path / str(index) for index in range(2)]
    for root in roots:
        root.mkdir()
    observed = False

    async def scan() -> None:
        await engine.run_scan(
            ScanOptions(timeout=30),
            servers=[_stdio_server("hang", root) for root in roots],
        )

    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(scan)
            while not all(list(root.glob("server-*.json")) for root in roots):
                await anyio.sleep(0.01)
            observed = True
            tasks.cancel_scope.cancel()
    assert observed
    assert mp.active_children() == []
    for root in roots:
        group = json.loads(next(root.glob("server-*.json")).read_text())["pgid"]
        await _assert_process_group_exited(group)
