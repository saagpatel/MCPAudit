"""Bounded newline-delimited stdio; SDK process lifecycle and handshake stay intact."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TextIO

import anyio
from anyio.abc import ByteReceiveStream
from mcp.client._transport import TransportStreams
from mcp.client.stdio import (
    StdioServerParameters,
    _aclose_all,
    _create_platform_compatible_process,
    _drain_stdout,
    _get_executable_command,
    _parse_line,
    _stop_server_process,
    get_default_environment,
)
from mcp.shared.message import SessionMessage

DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_SURFACE_BYTES = 64 * 1024 * 1024


class FrameSizeError(ValueError):
    """A server exceeded the frame cap before JSON parsing."""


async def read_lines(stream: ByteReceiveStream, max_frame_bytes: int) -> AsyncIterator[bytes]:
    """Scan each incoming byte once, retaining at most one bounded frame.

    The newline is excluded from the limit. As in the SDK, an unterminated
    final line is not delivered. UTF-8 decoding happens only on complete lines.
    """
    if max_frame_bytes < 1:
        raise ValueError("max_frame_bytes must be positive")
    buffer = bytearray()
    while True:
        try:
            chunk = await stream.receive(64 * 1024)
        except anyio.EndOfStream:
            return
        start = 0
        while start < len(chunk):
            newline = chunk.find(b"\n", start)
            end = newline if newline >= 0 else len(chunk)
            if len(buffer) + end - start > max_frame_bytes:
                raise FrameSizeError(f"Stdio frame size exceeds {max_frame_bytes} bytes.")
            buffer.extend(memoryview(chunk)[start:end])
            if newline < 0:
                break
            yield bytes(buffer)
            buffer.clear()
            start = newline + 1


@asynccontextmanager
async def bounded_stdio_client(
    server: StdioServerParameters, *, errlog: TextIO, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
) -> AsyncIterator[TransportStreams]:
    """Replace only the SDK reader, keeping its curated env and process helpers.

    These private lifecycle helpers are deliberately shared with the locked
    SDK 2.x family; connector integration tests guard that compatibility seam.
    """
    if max_frame_bytes < 1:
        raise ValueError("max_frame_bytes must be positive")
    command = await _get_executable_command(server.command)
    process = await _create_platform_compatible_process(
        command, server.args, get_default_environment() | (server.env or {}), errlog, server.cwd
    )
    read_writer, read = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write, write_reader = anyio.create_memory_object_stream[SessionMessage](0)
    writer_done = anyio.Event()
    reader_done = anyio.Event()
    shutting_down = False

    async def reader() -> None:
        assert process.stdout
        try:
            async with read_writer:
                async for line in read_lines(process.stdout, max_frame_bytes):
                    try:
                        await read_writer.send(
                            _parse_line(line.decode(server.encoding, errors=server.encoding_error_handler))
                        )
                    except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                        return  # The session closed its receiving stream.
        except anyio.ClosedResourceError:
            if not shutting_down:
                raise
        finally:
            reader_done.set()

    async def drain() -> None:
        # Drain concurrently with failure propagation and shutdown, so a
        # server blocked writing an oversized frame can observe stdin EOF.
        with anyio.CancelScope(shield=True):
            await reader_done.wait()
            await _drain_stdout(process)

    async def writer() -> None:
        assert process.stdin
        try:
            async with write_reader:
                async for message in write_reader:
                    data = message.message.model_dump_json(by_alias=True, exclude_unset=True) + "\n"
                    await process.stdin.send(
                        data.encode(server.encoding, errors=server.encoding_error_handler)
                    )
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            await read_writer.aclose()
        finally:
            writer_done.set()

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(reader)
        tasks.start_soon(writer)
        tasks.start_soon(drain)
        try:
            yield read, write
        finally:
            shutting_down = True
            with anyio.CancelScope(shield=True):
                read.close()
                write.close()
                with anyio.move_on_after(0.5):
                    await writer_done.wait()
                await _stop_server_process(process)
                await _aclose_all(read, write, read_writer, write_reader)
            tasks.cancel_scope.cancel()
