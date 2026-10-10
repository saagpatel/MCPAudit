"""Acceptance checks for bounded transport and server process hygiene."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

import anyio
import httpx2
import pytest

from mcp_audit.connector import ServerConnector
from mcp_audit.http_transport import BoundedHttpClient, HttpBodySizeError
from mcp_audit.models import ServerConfig, TransportType
from tests.conftest import make_server_config

FIXTURES = Path(__file__).parent / "fixtures"
BODY_LIMIT = 16 * 1024 * 1024


def _stdio_server(mode: str, root: Path) -> ServerConfig:
    return make_server_config(
        command=sys.executable,
        args=["-I", str(FIXTURES / "transport_hygiene_server.py"), mode, str(root)],
    )


def _process_group(root: Path) -> int:
    records = [json.loads(path.read_text()) for path in root.glob("server-*.json")]
    assert len(records) == 1
    group = records[0]["pgid"]
    assert isinstance(group, int) and group > 1 and group != os.getpgrp()
    return group


def _group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


async def _connect_http_probe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        headers = await reader.readuntil(b"\r\n\r\n")
        content_length = 0
        for line in headers.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.lower() == b"content-length":
                content_length = int(value.strip())
                break
        if content_length:
            await reader.readexactly(content_length)
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        body = b'{"jsonrpc":"2.0","id":1,"result":{"padding":"' + b"x" * 65536
        chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n"
        while True:
            writer.write(chunk)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        # The scanner hangs up at its cap; a reset while closing is the expected outcome.
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


class _Chunks(httpx2.AsyncByteStream):
    def __init__(self, chunk_size: int) -> None:
        self.chunk_size = chunk_size
        self.emitted = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            self.emitted += self.chunk_size
            yield b"x" * self.chunk_size

    async def aclose(self) -> None:
        pass


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["malformed", "malformed-flood"])
async def test_malformed_handshake_fails_immediately_with_one_safe_protocol_log(
    mode: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    started = time.perf_counter()
    with caplog.at_level(logging.DEBUG):
        audit = await ServerConnector(timeout=5).connect(_stdio_server(mode, tmp_path))
    elapsed = time.perf_counter() - started
    assert audit.connection_status == "failed"
    assert audit.connection_error and "protocol_error" in audit.connection_error
    assert "synthetic-secret" not in audit.connection_error
    protocol_logs = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Server test-server protocol_error:")
    ]
    assert len(protocol_logs) == 1
    assert "synthetic-secret" not in "\n".join(protocol_logs)
    assert "Failed to parse JSONRPC message" not in caplog.text
    assert elapsed < 1


@pytest.mark.anyio
async def test_connection_error_includes_bounded_redacted_stderr_tail(tmp_path: Path) -> None:
    audit = await ServerConnector(timeout=5).connect(_stdio_server("stderr-malformed", tmp_path))
    error = audit.connection_error or ""
    assert audit.connection_status == "failed"
    assert "diagnostic marker" in error
    assert "synthetic-secret" not in error
    assert len(error.encode()) < 12 * 1024


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["spawn-child-exit", "spawn-child-ignore"])
@pytest.mark.parametrize("sdk_fallback", [False, True], ids=["bounded-stdio", "sdk-stdio"])
async def test_shutdown_removes_the_entire_stdio_process_group(
    mode: str, sdk_fallback: bool, tmp_path: Path
) -> None:
    audit = await ServerConnector(timeout=2, sdk_stdio_fallback=sdk_fallback).connect(
        _stdio_server(mode, tmp_path)
    )
    assert audit.connection_status in {"failed", "timeout"}
    group = _process_group(tmp_path)
    deadline = time.monotonic() + 2
    while _group_exists(group) and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert not _group_exists(group)


@pytest.mark.anyio
async def test_http_client_caps_streamed_response_body() -> None:
    stream = _Chunks(chunk_size=4096)
    transport = httpx2.MockTransport(lambda request: httpx2.Response(200, stream=stream))
    async with BoundedHttpClient(max_body_bytes=16_384, transport=transport) as client:
        with pytest.raises(HttpBodySizeError, match="HTTP body size exceeds 16384 bytes"):
            await client.get("https://fixture.invalid/")
    assert stream.emitted == 20_480


@pytest.mark.anyio
async def test_http_malformed_json_withholds_parse_input_and_tracebacks(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def factory() -> BoundedHttpClient:
        return BoundedHttpClient(
            transport=httpx2.MockTransport(
                lambda request: httpx2.Response(
                    200, content=b"{bad synthetic-secret", headers={"Content-Type": "application/json"}
                )
            )
        )

    monkeypatch.setattr("mcp_audit.connector.create_mcp_http_client", factory)
    connector = ServerConnector(timeout=5)
    warnings = connector.scan_warnings = []
    config = make_server_config(transport=TransportType.HTTP, url="https://fixture.invalid/mcp")
    started = time.monotonic()
    with caplog.at_level(logging.DEBUG):
        audit = await connector.connect(config)
    assert time.monotonic() - started < 1
    assert audit.connection_status == "failed"
    assert audit.connection_error and "protocol_error" in audit.connection_error
    assert "synthetic-secret" not in audit.connection_error + caplog.text
    assert "Error parsing JSON response" not in caplog.text
    assert any(w.code == "protocol_error" for w in warnings)


@pytest.mark.anyio
async def test_connector_http_cap_is_applied_through_sdk_client_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _Chunks(chunk_size=4096)

    def factory() -> BoundedHttpClient:
        return BoundedHttpClient(
            transport=httpx2.MockTransport(
                lambda request: httpx2.Response(
                    200, stream=stream, headers={"Content-Type": "application/json"}
                )
            )
        )

    monkeypatch.setattr("mcp_audit.connector.create_mcp_http_client", factory)
    connector = ServerConnector(timeout=2, max_frame_bytes=16_384)
    config = make_server_config(transport=TransportType.HTTP, url="https://fixture.invalid/mcp")
    started = time.monotonic()
    audit = await connector.connect(config)
    assert audit.connection_status == "failed"
    assert audit.connection_error and "HTTP body size exceeds 16384 bytes" in audit.connection_error
    assert time.monotonic() - started < 2 + 4.5
    assert stream.emitted == 20_480


class _SseComments(_Chunks):
    def __init__(self, overflow: anyio.Event) -> None:
        super().__init__(chunk_size=4096)
        self.overflow = overflow
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            self.emitted += self.chunk_size
            if self.emitted > 16_384:
                self.overflow.set()
            yield b":" + b"x" * (self.chunk_size - 3) + b"\n\n"

    async def aclose(self) -> None:
        self.closed = True


class _SseEndpoint(httpx2.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"event: endpoint\ndata: /messages\n\n"
        await anyio.sleep_forever()

    async def aclose(self) -> None:
        pass


@pytest.mark.anyio
@pytest.mark.parametrize("transport", [TransportType.HTTP, TransportType.SSE])
async def test_body_overflow_cancels_session_even_when_sdk_swallows_error(
    transport: TransportType, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    overflow = anyio.Event()
    stream = _SseComments(overflow)
    get_requests = 0

    async def respond(request: httpx2.Request) -> httpx2.Response:
        nonlocal get_requests
        if request.method == "GET":
            get_requests += 1
            return httpx2.Response(
                200,
                stream=stream if transport == TransportType.HTTP else _SseEndpoint(),
                headers={"Content-Type": "text/event-stream"},
            )
        if request.method == "DELETE":
            return httpx2.Response(200)
        if transport == TransportType.SSE:
            # Legacy SSE POST reads the body, then its writer swallows the exception.
            return httpx2.Response(200, stream=stream)
        message = json.loads(request.content)
        if "id" not in message:
            return httpx2.Response(202)
        payload: dict[str, object] = {"jsonrpc": "2.0", "id": message["id"]}
        headers = {"Content-Type": "application/json"}
        if message["method"] == "initialize":
            headers["mcp-session-id"] = "fixture-session"
            payload["result"] = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture", "version": "1"},
            }
        elif message["method"] == "tools/list":
            # Without the failure latch, GET overflow would still allow a complete audit.
            await overflow.wait()
            payload["result"] = {"tools": []}
        else:
            payload["error"] = {"code": -32601, "message": "Method not found"}
        return httpx2.Response(200, json=payload, headers=headers)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
    ) -> BoundedHttpClient:
        return BoundedHttpClient(
            headers=headers, timeout=timeout, auth=auth, transport=httpx2.MockTransport(respond)
        )

    monkeypatch.setattr("mcp_audit.connector.create_mcp_http_client", factory)
    connector = ServerConnector(timeout=5, max_frame_bytes=16_384)
    warnings = connector.scan_warnings = []
    config = make_server_config(transport=transport, url="https://fixture.invalid/mcp")
    started = time.monotonic()
    with caplog.at_level(logging.DEBUG):
        audit = await connector.connect(config)
    assert time.monotonic() - started < 1
    assert audit.connection_status == "failed"
    assert audit.connection_error and "HTTP body size exceeds 16384 bytes" in audit.connection_error
    assert audit.tools == []
    assert any(w.code == "protocol_error" for w in warnings)
    assert get_requests == 1
    assert stream.emitted == 20_480
    assert stream.closed
    protocol_logs = [
        r for r in caplog.records if r.getMessage().startswith("Server test-server protocol_error:")
    ]
    assert len(protocol_logs) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({"Content-Encoding": "gzip"}, "Compressed HTTP bodies are not supported"),
        ({"Content-Length": "16385"}, "HTTP body size exceeds 16384 bytes"),
    ],
)
async def test_http_client_rejects_compressed_and_oversized_headers(
    headers: dict[str, str], reason: str
) -> None:
    stream = _Chunks(chunk_size=4096)
    transport = httpx2.MockTransport(lambda request: httpx2.Response(200, headers=headers, stream=stream))
    async with BoundedHttpClient(max_body_bytes=16_384, transport=transport) as client:
        with pytest.raises(HttpBodySizeError, match=reason):
            await client.get("https://fixture.invalid/")
    assert stream.emitted == 0


@pytest.mark.anyio
async def test_hostile_stdio_server_finishes_within_timeout_plus_grace(tmp_path: Path) -> None:
    timeout = 0.5
    started = time.perf_counter()
    audit = await ServerConnector(timeout=timeout).connect(_stdio_server("hang", tmp_path))
    elapsed = time.perf_counter() - started
    assert audit.connection_status == "timeout"
    assert elapsed < timeout + 4.5


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mode",
    ["silent", "slow-bytes", "wrong-id", "wrong-id-list", "notification-flood", "stderr-flood"],
)
async def test_hostile_fixture_modes_obey_session_wall_bound(
    mode: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for directory in ("home", "pids"):
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    config = make_server_config(
        command=sys.executable,
        args=[
            "-I",
            "-S",
            str(FIXTURES / "hostile_server.py"),
            mode,
            "--work-dir",
            str(tmp_path),
            "--ignore-sigterm",
        ],
    )
    timeout = 1
    started = time.monotonic()
    audit = await ServerConnector(timeout=timeout).connect(config)
    assert time.monotonic() - started < timeout + 4.5
    assert audit.connection_status in {"connected", "timeout", "failed"}


@pytest.mark.anyio
@pytest.mark.parametrize("denied", [False, True], ids=["survivor", "denied-observation"])
async def test_unverified_shutdown_emits_one_orphan_warning(
    denied: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_killpg = os.killpg
    signals: list[int] = []

    def simulate_survivor(group: int, sig: int) -> None:
        if sig == 0:
            if denied:
                raise PermissionError("fixture process-query denial")
            return
        signals.append(sig)
        real_killpg(group, sig)  # Still clean up the real owned fixture.

    monkeypatch.setattr(os, "killpg", simulate_survivor)
    connector = ServerConnector(timeout=5)
    warnings = connector.scan_warnings = []
    server = _stdio_server("malformed", tmp_path)
    audit = await connector.connect(server)
    assert audit.connection_status == "failed"
    assert signals == [15, 9]
    assert len(warnings) == 2  # One protocol error and one cleanup warning.
    orphans = [w for w in warnings if w.code == "orphan_processes"]
    assert len(orphans) == 1 and orphans[0].servers == [server.name]
    assert orphans[0].check == "connection"


@pytest.mark.anyio
async def test_endless_local_http_body_hits_default_cap_in_isolated_scanner(tmp_path: Path) -> None:
    server = await asyncio.start_server(_connect_http_probe, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    fixture_home = tmp_path / "home"
    fixture_home.mkdir()
    env = {
        "HOME": str(fixture_home),
        "PATH": os.defpath,
        "TMPDIR": str(tmp_path),
        "XDG_CONFIG_HOME": str(fixture_home),
        "XDG_CACHE_HOME": str(fixture_home),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    command = [
        sys.executable,
        str(FIXTURES / "http_transport_probe.py"),
        f"http://127.0.0.1:{port}/mcp",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    started = time.perf_counter()
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=6.5)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise AssertionError("HTTP body probe exceeded timeout plus 4.5 seconds") from None
    finally:
        server.close()
        await server.wait_closed()
    elapsed = time.perf_counter() - started
    assert process.returncode == 0, stderr.decode(errors="replace")
    result = json.loads(stdout)
    assert result["status"] == "failed"
    error = result["error"]
    assert isinstance(error, str) and "body size" in error.lower()
    assert str(BODY_LIMIT) in error
    assert result["peak_rss_bytes"] < 300_000_000
    assert elapsed < 6.5


@pytest.mark.anyio
async def test_default_http_body_cap_bounds_isolated_process_rss(tmp_path: Path) -> None:
    fixture_home = tmp_path / "home"
    fixture_home.mkdir()
    env = {
        "HOME": str(fixture_home),
        "PATH": os.defpath,
        "TMPDIR": str(tmp_path),
        "XDG_CONFIG_HOME": str(fixture_home),
        "XDG_CACHE_HOME": str(fixture_home),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(FIXTURES / "http_transport_probe.py"),
        "--mock",
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=6.5)
    assert process.returncode == 0, stderr.decode(errors="replace")
    result = json.loads(stdout)
    assert result["error"] == f"HTTP body size exceeds {BODY_LIMIT} bytes."
    assert result["body_bytes"] == BODY_LIMIT + 65_536
    assert result["peak_rss_bytes"] < 300_000_000
