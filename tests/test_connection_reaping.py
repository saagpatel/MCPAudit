"""Event-gated local fixtures for session admission and awaited process reaping."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

import anyio
import pytest
from anyio.abc import AsyncResource
from mcp.client.stdio import _close_pipe, _create_platform_compatible_process
from mcp.os.win32.utilities import ServerProcess

from mcp_audit import stdio_transport
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport
from tests.conftest import make_server_config

FIXTURE = Path(__file__).parent / "fixtures" / "transport_hygiene_server.py"


class ReapGate:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, limit: int) -> None:
        self.limit = limit
        self.release = anyio.Event()
        self.pool_full = anyio.Event()
        self.live_full = anyio.Event()
        self.first_spawn = anyio.Event()
        self.spawned: list[ServerProcess] = []
        self.reaped: list[ServerProcess] = []
        self.active = 0
        self.peak_active = 0
        self.peak_live = 0
        self.closed: list[AsyncResource] = []
        self.warning = False
        self.error = False
        spawn = _create_platform_compatible_process
        reap = stdio_transport._stop_process_group
        close = _close_pipe

        async def tracked_spawn(
            command: str,
            args: list[str],
            env: dict[str, str] | None,
            errlog: TextIO,
            cwd: Path | str | None,
        ) -> ServerProcess:
            process = await spawn(command, args, env, errlog, cwd)
            self.spawned.append(process)
            self.first_spawn.set()
            live = len(self.spawned) - len(self.reaped)
            self.peak_live = max(self.peak_live, live)
            if live == 2 * limit:
                self.live_full.set()
            return process

        async def tracked_close(stream: AsyncResource) -> None:
            await close(stream)
            self.closed.append(stream)

        async def gated_reap(process: ServerProcess, on_orphans: Callable[[str], None]) -> None:
            assert process.stdin in self.closed  # EOF precedes admission to the reaper pool.
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            if self.active == limit:
                self.pool_full.set()
            try:
                await self.release.wait()
                await reap(process, on_orphans)
                if self.warning:
                    on_orphans("Synthetic cleanup warning.")
                if self.error:
                    raise OSError("Synthetic reaping failure.")
            finally:
                self.reaped.append(process)
                self.active -= 1

        monkeypatch.setattr(stdio_transport, "_create_platform_compatible_process", tracked_spawn)
        monkeypatch.setattr(stdio_transport, "_close_pipe", tracked_close)
        monkeypatch.setattr(stdio_transport, "_stop_process_group", gated_reap)

    def assert_clean(self) -> None:
        assert self.peak_active <= self.limit
        assert self.peak_live <= 2 * self.limit
        assert self.active == 0
        assert {p.pid for p in self.spawned} == {p.pid for p in self.reaped}
        for process in self.spawned:
            assert process.returncode is not None
            if os.name == "posix":
                with pytest.raises(ProcessLookupError):
                    os.killpg(process.pid, 0)


@pytest.mark.anyio
@pytest.mark.parametrize("limit", [1, 2])
@pytest.mark.parametrize("canary", [False, True])
async def test_scan_releases_sessions_before_bounded_reaping_and_joins_all_reapers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, limit: int, canary: bool
) -> None:
    gate = ReapGate(monkeypatch, limit)
    servers = [
        make_server_config(
            name=f"fixture-{i}",
            command=sys.executable,
            args=["-I", "-S", str(FIXTURE), "normal", str(tmp_path)],
        )
        for i in range(3 * limit + 1)
    ]
    done = anyio.Event()
    reports: list[AuditReport] = []

    async def scan() -> None:
        reports.append(
            await run_scan(ScanOptions(max_concurrency=limit, canary_check=canary), servers=servers)
        )
        done.set()

    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(scan)
            try:
                await gate.pool_full.wait()
                # A second wave spawns while the first wave's reapers are blocked.
                await gate.live_full.wait()
                await anyio.wait_all_tasks_blocked()
                assert len(gate.spawned) == 2 * limit
                assert not done.is_set()
            finally:
                gate.release.set()
            await done.wait()

    assert gate.peak_active == limit
    assert gate.peak_live == 2 * limit
    assert len(gate.spawned) == len(servers) * (2 if canary else 1)
    assert all(a.connection_status == "connected" for a in reports[0].audits)
    gate.assert_clean()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["cancel", "cancel_reaping", "timeout", "warning", "error"])
async def test_scan_reaps_all_owned_groups_on_cancellation_timeout_and_cleanup_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    gate = ReapGate(monkeypatch, 1)
    gate.warning = mode == "warning"
    gate.error = mode == "error"
    fixture_mode = "hang" if mode in {"cancel", "timeout"} else "normal"
    servers = [
        make_server_config(
            name=f"fixture-{i}",
            command=sys.executable,
            args=["-I", "-S", str(FIXTURE), fixture_mode, str(tmp_path)],
        )
        for i in range(3)
    ]
    scope = anyio.CancelScope()
    done = anyio.Event()
    reports: list[AuditReport] = []

    async def scan() -> None:
        with scope:
            reports.append(await run_scan(ScanOptions(max_concurrency=1, timeout=1), servers=servers))
        done.set()

    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(scan)
            try:
                if mode == "cancel":
                    # Cancel after a child starts, not just a queued scan.
                    await gate.first_spawn.wait()
                    scope.cancel()
                elif mode == "cancel_reaping":
                    await gate.live_full.wait()
                    await anyio.wait_all_tasks_blocked()
                    scope.cancel()
                await gate.pool_full.wait()
                await anyio.wait_all_tasks_blocked()
                assert not done.is_set()
            finally:
                gate.release.set()
            await done.wait()

    gate.assert_clean()
    if mode.startswith("cancel"):
        assert scope.cancelled_caught and reports == []
    elif mode == "timeout":
        assert all(a.connection_status == "timeout" for a in reports[0].audits)
    elif mode == "warning":
        assert len([w for w in reports[0].warnings if w.code == "orphan_processes"]) == len(servers)
    else:
        assert all(a.connection_status == "failed" for a in reports[0].audits)
        assert all("Synthetic reaping failure" in (a.connection_error or "") for a in reports[0].audits)
