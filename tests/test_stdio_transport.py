"""Frame boundaries, listing caps and SDK compatibility on synthetic inputs."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest
from anyio.abc import ByteReceiveStream
from click.testing import CliRunner
from mcp.types import ListToolsResult, Tool

from mcp_audit.connector import ServerConnector, _list_pages
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.stdio_transport import FrameSizeError, read_lines
from mcp_audit.surface_limits import ListingBudget, SurfaceLimitError
from mcp_audit.text_limits import MAX_FIELD_BYTES
from tests.conftest import make_server_config

FIXTURES = Path(__file__).parent / "fixtures"


class ChunkStream(ByteReceiveStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = iter(chunks)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        try:
            return next(self.chunks)
        except StopIteration:
            raise anyio.EndOfStream from None

    async def aclose(self) -> None:
        pass


@pytest.mark.anyio
@pytest.mark.parametrize(
    "chunks", [[b"abc\n\n", b"\xf0\x9f", b"\x99\x82\nxyz"], [b"abc\n\n\xf0\x9f\x99\x82\nxyz"]]
)
async def test_lines_keep_boundaries_and_drop_unterminated_tail(chunks: list[bytes]) -> None:
    assert [line async for line in read_lines(ChunkStream(chunks), 4)] == [b"abc", b"", "🙂".encode()]


@pytest.mark.anyio
@pytest.mark.parametrize("chunks", [[b"12345\n"], [b"1234", b"5"], [b"ok\n12345\n"]])
async def test_frame_limit_applies_before_newline_and_after_previous_frame(chunks: list[bytes]) -> None:
    with pytest.raises(FrameSizeError, match="frame size exceeds 4 bytes"):
        _ = [line async for line in read_lines(ChunkStream(chunks), 4)]


@pytest.mark.anyio
async def test_listing_budget_charges_original_bytes_across_pages() -> None:
    pages = [
        ListToolsResult(tools=[Tool(name=f"t{i}", input_schema={})], next_cursor=str(i + 1)) for i in range(3)
    ]
    size = len(pages[0].model_dump_json(by_alias=True).encode())
    calls = 0

    async def fetch(*, cursor: str | None, cache_mode: str) -> ListToolsResult:
        nonlocal calls
        calls += 1
        assert cache_mode == "bypass"
        return pages[int(cursor or 0)]

    with pytest.raises(SurfaceLimitError):
        await _list_pages(fetch, lambda page: page.tools, budget=ListingBudget(size * 2))
    assert calls == 2  # No additional fetch after the shared budget is exhausted.


def test_item_cap_preserves_identity_and_bounds_nested_unicode_text() -> None:
    tool = Tool(
        name="status",
        description="🙂" * MAX_FIELD_BYTES,
        input_schema={"type": "object", "properties": {"arg": {"description": "suffix"}}},
    )
    budget = ListingBudget()
    capped = budget.cap_item(tool)
    assert capped.name == tool.name
    assert capped.input_schema["type"] == "object"
    assert capped.description and len(capped.description.encode()) <= MAX_FIELD_BYTES
    assert len(capped.model_dump_json().encode()) < MAX_FIELD_BYTES + 512
    assert budget.truncated_items == 1
    assert tool.description == "🙂" * MAX_FIELD_BYTES


def test_oversized_identifiers_are_rejected_instead_of_renamed() -> None:
    with pytest.raises(SurfaceLimitError, match="identifiers"):
        ListingBudget().cap_item(Tool(name="n" * MAX_FIELD_BYTES, input_schema={}))


@pytest.mark.anyio
@pytest.mark.parametrize("surface", ["tools", "prompts", "resources"])
async def test_connected_listing_text_is_capped_and_coverage_is_partial(surface: str) -> None:
    server = make_server_config(
        command=sys.executable, args=[str(FIXTURES / "bounded_surface_server.py"), surface, "100000"]
    )
    report = await run_scan(ScanOptions(config_only=True), servers=[server])
    audit = report.audits[0]
    assert audit.connection_status == "partial"
    assert len(audit.tools) == len(audit.prompts) == len(audit.resources) == 1
    assert any(w.code == "surface_truncated" and w.servers == [server.name] for w in report.warnings)
    assert report.coverage["metadata"].state == "partial"
    assert report.coverage["permissions"].state == "partial"
    if surface == "tools":
        text = audit.tools[0].description
    elif surface == "prompts":
        text = audit.prompts[0].argument_details[0].description
    else:
        text = audit.resources[0].description
    assert text and len(text.encode()) <= MAX_FIELD_BYTES


@pytest.mark.anyio
async def test_truncated_metadata_cannot_select_canary_tools() -> None:
    connector = ServerConnector(timeout=5)
    server = make_server_config(
        command=sys.executable, args=[str(FIXTURES / "bounded_surface_server.py"), "tools", "100000"]
    )
    audit = await connector.connect(server, canary_calls=1, canary_identities=1)
    assert audit.connection_status == "partial"
    assert audit.canary and audit.canary.completed_calls == 0 and audit.canary.status == "partial"


@pytest.mark.anyio
@pytest.mark.parametrize("surface", ["pages", "resources"])
async def test_budget_spans_pages_and_different_surfaces(surface: str) -> None:
    connector = ServerConnector(timeout=5, max_surface_bytes=1200)
    server = make_server_config(
        command=sys.executable, args=[str(FIXTURES / "bounded_surface_server.py"), surface, "100"]
    )
    warnings = connector.scan_warnings = []
    audit = await connector.connect(server)
    assert audit.connection_status == "partial"
    assert any(w.code == "surface_listing_incomplete" and "1200 bytes" in w.message for w in warnings)
    if surface == "pages":
        assert not audit.tools
    else:
        assert audit.tools and audit.prompts and not audit.resources


@pytest.mark.anyio
async def test_sdk_fallback_bypasses_only_frame_cap_and_preserves_handshake() -> None:
    server = make_server_config(command=sys.executable, args=[str(FIXTURES / "mock_server.py")])
    bounded = await ServerConnector(timeout=5, max_frame_bytes=1).connect(server)
    assert bounded.connection_status == "failed" and bounded.connection_error
    assert "frame size" in bounded.connection_error
    fallback = await ServerConnector(timeout=5, max_frame_bytes=1, sdk_stdio_fallback=True).connect(server)
    normal = await ServerConnector(timeout=5).connect(server)
    assert fallback.connection_status == normal.connection_status == "connected"
    assert fallback.tools == normal.tools and fallback.prompts == normal.prompts
    assert fallback.protocol == normal.protocol


@pytest.mark.parametrize("command", ["scan", "check"])
def test_cli_transmits_transport_options(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.cli import main

    captured: list[ScanOptions] = []

    async def stop_at_engine(options: ScanOptions, **kwargs: object) -> None:
        captured.append(options)
        raise ValueError("synthetic engine boundary")

    module = "scan_cli" if command == "scan" else "check_cli"
    monkeypatch.setattr(f"mcp_audit.{module}.run_scan", stop_at_engine)
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers":{}}')
    args = [
        command,
        "--config",
        str(config),
        "--override-config",
        "/dev/null",
        "--max-frame-bytes",
        "1234",
        "--max-surface-bytes",
        "5678",
        "--sdk-stdio-fallback",
    ]
    if command == "scan":
        args += ["--config-only", "--skip-connect"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1 and "synthetic engine boundary" in result.output
    [options] = captured
    assert options.max_frame_bytes == 1234 and options.max_surface_bytes == 5678
    assert options.sdk_stdio_fallback is True


@pytest.mark.parametrize("command", ["scan", "check"])
@pytest.mark.parametrize("flag", ["--max-frame-bytes", "--max-surface-bytes"])
def test_cli_byte_caps_reject_zero(command: str, flag: str) -> None:
    from mcp_audit.cli import main

    assert CliRunner().invoke(main, [command, flag, "0"]).exit_code == 2
