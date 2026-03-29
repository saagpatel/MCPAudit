"""Runtime monitor — proxy a live MCP server and log tool call traffic."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import anyio.abc
import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from mcp_audit.discovery import discover_all_configs

logger = logging.getLogger(__name__)

_console = Console()

# MCP stdio framing: "Content-Length: N\r\n\r\n<json>"
_CONTENT_LENGTH_HEADER = b"Content-Length: "


async def _read_message(stream: anyio.abc.ByteReceiveStream) -> dict[str, Any] | None:
    """Read one LSP-framed JSON-RPC message from a byte stream. Returns None on EOF."""
    # Read headers until \r\n\r\n
    header_buf = bytearray()
    while True:
        try:
            chunk = await stream.receive(1)
        except (anyio.EndOfStream, anyio.ClosedResourceError):
            return None
        header_buf.extend(chunk)
        if header_buf.endswith(b"\r\n\r\n"):
            break

    # Parse Content-Length
    content_length = 0
    for line in header_buf.split(b"\r\n"):
        if line.startswith(_CONTENT_LENGTH_HEADER):
            try:
                content_length = int(line[len(_CONTENT_LENGTH_HEADER) :].strip())
            except ValueError:
                pass
            break

    if content_length <= 0:
        return None

    # Read body
    body = bytearray()
    remaining = content_length
    while remaining > 0:
        try:
            chunk = await stream.receive(min(remaining, 4096))
        except (anyio.EndOfStream, anyio.ClosedResourceError):
            break
        body.extend(chunk)
        remaining -= len(chunk)

    try:
        return json.loads(body.decode("utf-8"))  # type: ignore[no-any-return]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _frame_message(msg: dict[str, Any]) -> bytes:
    """Encode a JSON-RPC message with LSP framing."""
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    return header + body


class MCPProxyMonitor:
    """Intercepts stdio between MCP client and server, logging tool calls."""

    def __init__(self, log_path: Path | None = None) -> None:
        self._log_path = log_path
        self._log_file = open(log_path, "a") if log_path else None  # noqa: SIM115
        # Per-tool stats: {tool_name: {"calls": int, "errors": int, "total_ms": float}}
        self._stats: dict[str, dict[str, float]] = {}
        # Pending requests by id
        self._pending: dict[int | str, tuple[str, str, datetime]] = {}  # id → (method, tool, ts)

    async def run(self, command: str, args: list[str], env: dict[str, str] | None = None) -> None:
        """Spawn server process and proxy stdio, logging tool calls."""
        async with await anyio.open_process(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            env=env,
        ) as process:
            _console.print(f"[dim]Monitoring server process (pid={process.pid}). Ctrl+C to stop.[/dim]")
            with Live(self._make_table(), refresh_per_second=2, console=_console) as live:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(
                        self._proxy_direction,
                        sys.stdin.buffer,
                        process.stdin,
                        "→ server",
                        live,
                    )
                    tg.start_soon(
                        self._proxy_direction,
                        process.stdout,
                        sys.stdout.buffer,
                        "← client",
                        live,
                    )

        if self._log_file:
            self._log_file.close()

    async def _proxy_direction(
        self,
        src: Any,
        dst: Any,
        direction: str,
        live: Live,
    ) -> None:
        """Forward messages from src to dst, intercepting tool calls/responses."""
        while True:
            msg = await _read_message(src)
            if msg is None:
                break
            framed = _frame_message(msg)
            try:
                await dst.send(framed)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                break
            self._intercept(msg, direction)
            live.update(self._make_table())

    def _intercept(self, msg: dict[str, Any], direction: str) -> None:
        """Parse and log tool call requests and responses."""
        now = datetime.now(UTC)
        ts = now.isoformat()

        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "tools/call" and direction == "→ server":
            params: dict[str, Any] = msg.get("params", {})
            tool_name: str = params.get("name", "<unknown>")
            arg_keys = list(params.get("arguments", {}).keys())
            entry: dict[str, Any] = {
                "ts": ts,
                "direction": "request",
                "method": method,
                "tool": tool_name,
                "arg_keys": arg_keys,
                "id": msg_id,
            }
            self._log(entry)
            if msg_id is not None:
                self._pending[msg_id] = (method, tool_name, now)

        elif msg_id is not None and direction == "← client" and "result" in msg or "error" in msg:
            if msg_id in self._pending:
                _req_method, tool_name, req_ts = self._pending.pop(msg_id)
                duration_ms = (now - req_ts).total_seconds() * 1000
                error = msg.get("error")
                entry = {
                    "ts": ts,
                    "direction": "response",
                    "id": msg_id,
                    "tool": tool_name,
                    "duration_ms": round(duration_ms, 1),
                    "error": error,
                }
                self._log(entry)
                self._update_stats(tool_name, duration_ms, error is not None)

    def _update_stats(self, tool_name: str, duration_ms: float, is_error: bool) -> None:
        if tool_name not in self._stats:
            self._stats[tool_name] = {"calls": 0.0, "errors": 0.0, "total_ms": 0.0}
        self._stats[tool_name]["calls"] += 1
        self._stats[tool_name]["total_ms"] += duration_ms
        if is_error:
            self._stats[tool_name]["errors"] += 1

    def _log(self, entry: dict[str, Any]) -> None:
        if self._log_file:
            self._log_file.write(json.dumps(entry) + "\n")
            self._log_file.flush()

    def _make_table(self) -> Table:
        table = Table(title="MCP Tool Call Monitor", show_lines=False)
        table.add_column("Tool", style="cyan")
        table.add_column("Calls", style="bold", justify="right")
        table.add_column("Errors", style="red", justify="right")
        table.add_column("Avg Latency", justify="right")
        for tool_name, stats in sorted(self._stats.items()):
            calls = int(stats["calls"])
            errors = int(stats["errors"])
            avg = stats["total_ms"] / calls if calls > 0 else 0
            table.add_row(tool_name, str(calls), str(errors), f"{avg:.0f}ms")
        return table


@click.command("monitor")
@click.argument("server_name")
@click.option("--log", "log_path", default=None, metavar="PATH", help="Write JSONL log to PATH.")
def monitor_command(server_name: str, log_path: str | None) -> None:
    """Proxy a running MCP server and log tool call activity in real-time."""
    anyio.run(_run_monitor, server_name, log_path)


async def _run_monitor(server_name: str, log_path: str | None) -> None:
    servers = discover_all_configs(None)
    target = next((s for s in servers if s.name == server_name), None)
    if target is None:
        _console.print(f"[red]Server '{server_name}' not found in any MCP config.[/red]")
        raise SystemExit(1)
    if not target.command:
        _console.print(
            f"[red]Server '{server_name}' has no stdio command (HTTP transport not supported).[/red]"
        )
        raise SystemExit(1)

    monitor = MCPProxyMonitor(log_path=Path(log_path) if log_path else None)
    await monitor.run(
        command=target.command,
        args=target.args,
    )
