"""Tests for MCPProxyMonitor framing and interception logic."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import anyio
import anyio.abc
import pytest  # noqa: F401

from mcp_audit.monitor import MCPProxyMonitor, _frame_message, _read_message

# ---------------------------------------------------------------------------
# Minimal async stream helpers
# ---------------------------------------------------------------------------


class _ByteStream(anyio.abc.ByteReceiveStream):
    """In-memory byte stream for testing _read_message."""

    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if not self._data:
            raise anyio.EndOfStream
        chunk = bytes(self._data[:max_bytes])
        del self._data[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        pass


# ---------------------------------------------------------------------------
# _frame_message / _read_message
# ---------------------------------------------------------------------------


class TestFramingRoundTrip:
    @pytest.mark.anyio
    async def test_round_trips_simple_message(self) -> None:
        msg = {"method": "tools/call", "id": 1}
        framed = _frame_message(msg)
        stream = _ByteStream(framed)
        result = await _read_message(stream)
        assert result == msg

    @pytest.mark.anyio
    async def test_round_trips_large_message(self) -> None:
        msg = {"method": "tools/call", "params": {"data": "x" * 500}, "id": 99}
        framed = _frame_message(msg)
        stream = _ByteStream(framed)
        result = await _read_message(stream)
        assert result == msg

    @pytest.mark.anyio
    async def test_read_returns_none_on_eof(self) -> None:
        stream = _ByteStream(b"")
        result = await _read_message(stream)
        assert result is None

    @pytest.mark.anyio
    async def test_frame_produces_correct_content_length(self) -> None:
        msg = {"x": "hello"}
        framed = _frame_message(msg)
        body = json.dumps(msg).encode()
        header_line = f"Content-Length: {len(body)}\r\n\r\n".encode()
        assert framed.startswith(header_line)

    @pytest.mark.anyio
    async def test_read_handles_exact_body_length(self) -> None:
        # Craft a message manually and confirm read gets exactly the body
        body = b'{"id": 42}'
        header = f"Content-Length: {len(body)}\r\n\r\n".encode()
        stream = _ByteStream(header + body)
        result = await _read_message(stream)
        assert result is not None
        assert result["id"] == 42


# ---------------------------------------------------------------------------
# MCPProxyMonitor._intercept
# ---------------------------------------------------------------------------


def _make_monitor() -> MCPProxyMonitor:
    m = MCPProxyMonitor(log_path=None)
    m._log = MagicMock()  # type: ignore[method-assign]
    return m


class TestIntercept:
    def test_records_tool_call_request_in_pending(self) -> None:
        mon = _make_monitor()
        msg = {
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
            "id": 1,
        }
        mon._intercept(msg, "→ server")
        assert 1 in mon._pending
        _method, tool, _ts = mon._pending[1]
        assert tool == "read_file"

    def test_does_not_log_argument_values(self) -> None:
        mon = _make_monitor()
        msg = {
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/passwd", "encoding": "utf-8"}},
            "id": 2,
        }
        mon._intercept(msg, "→ server")
        assert mon._log.called
        logged_entry: dict = mon._log.call_args[0][0]
        # arg_keys present, but values never logged
        assert logged_entry["arg_keys"] == ["path", "encoding"]
        raw_str = json.dumps(logged_entry)
        assert "/etc/passwd" not in raw_str
        assert "utf-8" not in raw_str

    def test_response_updates_stats(self) -> None:
        mon = _make_monitor()
        ts = datetime.now(UTC)
        mon._pending[5] = ("tools/call", "list_files", ts)
        response = {"id": 5, "result": {"content": []}}
        mon._intercept(response, "← client")
        assert "list_files" in mon._stats
        assert mon._stats["list_files"]["calls"] == 1.0
        assert mon._stats["list_files"]["errors"] == 0.0

    def test_response_tracks_error(self) -> None:
        mon = _make_monitor()
        ts = datetime.now(UTC)
        mon._pending[7] = ("tools/call", "write_file", ts)
        response = {"id": 7, "error": {"code": -1, "message": "Permission denied"}}
        mon._intercept(response, "← client")
        assert mon._stats["write_file"]["errors"] == 1.0

    def test_unknown_id_response_ignored(self) -> None:
        mon = _make_monitor()
        response = {"id": 999, "result": {}}
        mon._intercept(response, "← client")
        assert mon._stats == {}

    def test_non_tool_call_request_not_logged(self) -> None:
        mon = _make_monitor()
        msg = {"method": "initialize", "params": {}, "id": 1}
        mon._intercept(msg, "→ server")
        assert not mon._log.called
        assert mon._pending == {}


# ---------------------------------------------------------------------------
# MCPProxyMonitor._make_table
# ---------------------------------------------------------------------------


class TestMakeTable:
    def test_empty_stats_returns_table_with_no_rows(self) -> None:
        from rich.table import Table

        mon = MCPProxyMonitor()
        table = mon._make_table()
        assert isinstance(table, Table)
        assert table.row_count == 0

    def test_table_has_one_row_per_tool(self) -> None:
        mon = MCPProxyMonitor()
        mon._stats = {
            "read_file": {"calls": 3.0, "errors": 0.0, "total_ms": 150.0},
            "write_file": {"calls": 1.0, "errors": 1.0, "total_ms": 50.0},
        }
        table = mon._make_table()
        assert table.row_count == 2
