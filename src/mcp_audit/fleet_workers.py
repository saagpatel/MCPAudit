"""Private spawn workers for the per-server stage of large, shardable fleets."""

from __future__ import annotations

import math
import multiprocessing as mp
import os
import signal
import threading
import time
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from queue import Empty, SimpleQueue
from types import TracebackType
from typing import TYPE_CHECKING

import anyio

from mcp_audit.models import CheckCoverage, ScanWarning, ServerAudit, ServerConfig
from mcp_audit.terminal_text import terminal_safe

if TYPE_CHECKING:
    from mcp_audit.engine import _ScanContext, _WorkerSetup

SHARD_THRESHOLD = 256
MAX_WORKERS = 8
MIN_WORKERS = 2
_POLL_SECONDS = 0.002
_SHUTDOWN_SECONDS = 2.0
_SERVER_INDEX: ContextVar[int] = ContextVar("worker_server_index")


def worker_count(context: _ScanContext) -> int:
    """Zero means the unchanged single-process path; the env hook is test-only."""
    opts = context.opts
    mode = os.environ.get("_MCP_AUDIT_SHARDING")
    if (
        mode == "off"
        or os.name != "posix"
        or "spawn" not in mp.get_all_start_methods()
        or mp.current_process().daemon
        or context.pin_store is not None
        or any(
            getattr(opts, option)
            for option in (
                "skip_connect",  # Published contract: --skip-connect never spawns a process.
                "canary_check",
                "llm_analysis",
                "pin_check",
                "escalation_check",
                "provenance_check",
                "integrity_check",
                "verify_artifacts",
                "download_artifacts",
            )
        )
    ):
        return 0
    from mcp_audit.overrides import OverrideApplier

    if type(context.applier) is not OverrideApplier:
        return 0  # Caller extensions may hold shared state or unpicklable resources.
    count = len(context.servers)
    if count <= SHARD_THRESHOLD and mode != "on":
        return 0
    cpus = os.cpu_count() or 1
    workers = min(cpus, math.ceil(count / SHARD_THRESHOLD), MAX_WORKERS)
    if mode == "on" and count >= MIN_WORKERS and cpus >= MIN_WORKERS:
        workers = max(MIN_WORKERS, workers)
    return workers if workers >= MIN_WORKERS else 0


@dataclass(frozen=True)
class _Acquire:
    index: int


@dataclass(frozen=True)
class _Release:
    index: int


@dataclass(frozen=True)
class _Group:
    pid: int
    started: bool


@dataclass(frozen=True)
class _Result:
    index: int
    audit: ServerAudit
    warnings: list[ScanWarning]
    completed: set[str]
    package_coverage: dict[str, CheckCoverage]


class _Warnings(list[ScanWarning]):
    def append(self, warning: ScanWarning) -> None:
        from mcp_audit.engine import _SERVER_WARNING_SINK

        sink = _SERVER_WARNING_SINK.get()
        super().append(warning)
        if sink is not None:
            sink.append(warning)


class _ConnectionBudget:
    """Local ceil limit plus parent-owned tokens, reclaimed even on SIGKILL.

    A multiprocessing semaphore would lose acquired slots when a worker dies.
    The parent instead grants/reclaims tokens over the worker's duplex pipe.
    """

    def __init__(self, channel: Connection, limit: int) -> None:
        self.channel = channel
        self.local = anyio.CapacityLimiter(limit)
        self.waiters: dict[int, anyio.Event] = {}

    async def grants(self) -> None:
        while True:
            while self.channel.poll():
                index: object = self.channel.recv()
                if not isinstance(index, int) or index not in self.waiters:
                    raise ValueError("Invalid worker connection grant")
                self.waiters[index].set()
            await anyio.sleep(_POLL_SECONDS)

    async def __aenter__(self) -> None:
        await self.local.acquire()
        index = _SERVER_INDEX.get()
        event = self.waiters[index] = anyio.Event()
        try:
            self.channel.send(_Acquire(index))
            await event.wait()
        except BaseException:
            self.local.release()
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        index = _SERVER_INDEX.get()
        del self.waiters[index]
        self.channel.send(_Release(index))
        self.local.release()


def _worker_main(
    channel: Connection, setup: _WorkerSetup, servers: list[tuple[int, ServerConfig]], concurrency: int
) -> None:
    # Every worker owns a group; server transports continue to own separate groups.
    os.setsid()

    async def run() -> None:
        from mcp_audit.engine import _SERVER_WARNING_SINK, _audit_one_guarded
        from mcp_audit.stdio_transport import _GROUP_OBSERVER

        budget = _ConnectionBudget(channel, concurrency)
        context = setup.context([server for _, server in servers], budget)
        context.connector.scan_warnings = _Warnings()
        group_token = _GROUP_OBSERVER.set(lambda pid, started: channel.send(_Group(pid, started)))

        async def analyze(local_index: int, index: int, server: ServerConfig) -> None:
            warnings: list[ScanWarning] = []
            warning_token = _SERVER_WARNING_SINK.set(warnings)
            index_token = _SERVER_INDEX.set(index)
            try:
                await _audit_one_guarded(context, local_index, server)
                channel.send(
                    _Result(
                        index,
                        context.audits[local_index],
                        warnings,
                        context.completed[local_index],
                        {check: cells[local_index] for check, cells in context.package_coverage.items()},
                    )
                )
            finally:
                _SERVER_INDEX.reset(index_token)
                _SERVER_WARNING_SINK.reset(warning_token)

        try:
            with anyio.CancelScope() as shutdown:
                previous = signal.signal(signal.SIGTERM, lambda signum, frame: shutdown.cancel())
                try:
                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(budget.grants)
                        async with anyio.create_task_group() as analyses:
                            for local_index, (index, server) in enumerate(servers):
                                analyses.start_soon(analyze, local_index, index, server)
                        tasks.cancel_scope.cancel()
                finally:
                    signal.signal(signal.SIGTERM, previous)
        finally:
            _GROUP_OBSERVER.reset(group_token)

    try:
        anyio.run(run)
    except Exception as exc:
        # Parent exit/result handling reports failure without printing raw
        # exception text (which may contain server-controlled metadata).
        raise SystemExit(1) from exc
    finally:
        channel.close()


@dataclass
class _Worker:
    process: BaseProcess
    channel: Connection
    indices: range
    groups: set[int] = field(default_factory=set)
    received: set[int] = field(default_factory=set)
    active: set[int] = field(default_factory=set)
    eof: bool = False
    finished: bool = False
    messages: SimpleQueue[object] = field(default_factory=SimpleQueue)
    reader: threading.Thread | None = None


@dataclass(frozen=True)
class _PipeClosed:
    pass


def _read_worker(worker: _Worker) -> None:
    # A partial pickle from a stalled worker must never block the parent's
    # event loop or its cancellation/timeout cleanup. Only this thread reads.
    try:
        while True:
            worker.messages.put(worker.channel.recv())
    except (EOFError, OSError):
        worker.messages.put(_PipeClosed())


def _group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    return True  # Permission denial propagates: it is not successful verification.


async def _clean_groups(worker: _Worker, context: _ScanContext) -> None:
    for pid in tuple(worker.groups):
        try:
            if not _group_exists(pid):
                worker.groups.discard(pid)
                continue
            os.killpg(pid, signal.SIGKILL)
            with anyio.move_on_after(0.5):
                while _group_exists(pid):
                    await anyio.sleep(0.01)
            if not _group_exists(pid):
                worker.groups.discard(pid)
                continue
            message = "Worker-owned server process group survived shutdown; cleanup is unverified."
        except PermissionError:
            message = "Worker-owned process-group cleanup was denied; cleanup is unverified."
        except ProcessLookupError:
            worker.groups.discard(pid)
            continue  # The group exited between the probe and the signal.
        context.warn(
            "orphan_processes",
            message,
            check="connection",
            servers=[context.servers[index].name for index in worker.indices],
        )


def _missing_results(worker: _Worker, context: _ScanContext, advance: Callable[[], None]) -> None:
    for index in worker.indices:
        if index in worker.received:
            continue
        server = context.servers[index]
        message = "Scan worker exited without a result; connection and analysis are incomplete."
        context.audits[index] = ServerAudit(
            server=server, connection_status="failed", connection_error=message
        )
        context.completed[index].clear()
        context.warn("worker_process_failed", message, check="connection", servers=[server.name])
        advance()


async def run_sharded(context: _ScanContext, count: int, advance: Callable[[], None]) -> None:
    from mcp_audit.engine import _WorkerSetup

    spawn = mp.get_context("spawn")
    setup = _WorkerSetup.from_context(context)
    concurrency = max(1, math.ceil(context.opts.max_concurrency / count))
    workers: list[_Worker] = []
    waiting: deque[tuple[_Worker, int]] = deque()
    warnings: dict[int, list[ScanWarning]] = {}

    def receive(worker: _Worker, *, shutting_down: bool = False) -> None:
        # Limit a burst so one busy pipe cannot starve sibling workers/cancellation.
        for _ in range(32):
            if worker.eof:
                return
            try:
                value = worker.messages.get_nowait()
            except Empty:
                return
            if isinstance(value, _PipeClosed):
                worker.eof = True
                return
            if isinstance(value, _Group):
                if value.started:
                    worker.groups.add(value.pid)
                else:
                    worker.groups.discard(value.pid)
            elif shutting_down:
                continue  # Only ownership messages matter during cancellation cleanup.
            elif isinstance(value, _Acquire) and value.index in worker.indices:
                waiting.append((worker, value.index))
            elif isinstance(value, _Release) and value.index in worker.active:
                worker.active.remove(value.index)
            elif isinstance(value, _Result) and value.index in worker.indices:
                index = value.index
                if index in worker.received:
                    raise ValueError("Duplicate worker result")
                worker.received.add(index)
                context.audits[index] = value.audit
                context.completed[index] = value.completed
                for check, cell in value.package_coverage.items():
                    context.package_coverage[check][index] = cell
                warnings[index] = value.warnings
                advance()
            else:
                raise ValueError("Invalid worker result")

    try:
        for number in range(count):
            indices = range(
                number * len(context.servers) // count, (number + 1) * len(context.servers) // count
            )
            parent, child = spawn.Pipe()
            process = spawn.Process(
                target=_worker_main,
                args=(child, setup, [(index, context.servers[index]) for index in indices], concurrency),
                name=f"mcp-audit-worker-{number}",
            )
            worker = _Worker(process, parent, indices)
            workers.append(worker)
            try:
                process.start()
                assert process.pid is not None
                worker.groups.add(process.pid)
                worker.reader = threading.Thread(target=_read_worker, args=(worker,))
                worker.reader.start()
            except Exception:
                # Includes spawn/pickling failures; use the same redacted missing-result path.
                worker.finished = True
                _missing_results(worker, context, advance)
            finally:
                child.close()

        while any(not worker.finished for worker in workers):
            for worker in workers:
                if worker.finished:
                    continue
                receive(worker)
                if worker.process.exitcode is not None and worker.eof:
                    worker.process.join()
                    assert not worker.process.is_alive()
                    worker.finished = True
                    worker.active.clear()  # Reclaim tokens after a crash, including HTTP connections.
                    await _clean_groups(worker, context)
                    _missing_results(worker, context, advance)
            while waiting and sum(len(worker.active) for worker in workers) < context.opts.max_concurrency:
                worker, index = waiting.popleft()
                if worker.finished:
                    continue
                try:
                    worker.channel.send(index)
                except (BrokenPipeError, EOFError):
                    continue  # The next poll classifies the exit and reclaims its slots.
                worker.active.add(index)
            await anyio.sleep(_POLL_SECONDS)
    finally:
        # Shield owned-process cleanup from caller cancellation/timeouts. SIGTERM
        # lets transports reap their groups first; SIGKILL bounds a stuck worker.
        with anyio.CancelScope(shield=True):
            for worker in workers:
                if worker.process.is_alive():
                    worker.process.terminate()
            deadline = time.monotonic() + _SHUTDOWN_SECONDS
            while any(worker.process.is_alive() for worker in workers) and time.monotonic() < deadline:
                for worker in workers:
                    if not worker.finished:
                        receive(worker, shutting_down=True)
                await anyio.sleep(_POLL_SECONDS)
            for worker in workers:
                if worker.process.is_alive():
                    worker.process.kill()
                if worker.process.pid is not None:
                    await anyio.to_thread.run_sync(worker.process.join, _SHUTDOWN_SECONDS)
                    if worker.process.is_alive():
                        raise RuntimeError("Scan worker survived shutdown; cleanup is unverified.")
                if worker.reader is not None:
                    await anyio.to_thread.run_sync(worker.reader.join, _SHUTDOWN_SECONDS)
                    if worker.reader.is_alive():
                        raise RuntimeError("Scan worker result reader survived shutdown.")
                if not worker.finished:
                    while not worker.eof and not worker.messages.empty():
                        receive(worker, shutting_down=True)
                await _clean_groups(worker, context)
                worker.channel.close()
                worker.process.close()

    # The parent merges in configuration order, preserving within-server arrival
    # order. Finalization retains the documented report warning sort afterwards.
    for index in sorted(warnings):
        for warning in warnings[index]:
            context.scan_warnings.append(warning)
            context.out.print(terminal_safe(warning.message), style="yellow")
