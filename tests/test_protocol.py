"""Connected protocol observation through synthetic peers only."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import httpx2
import pytest
from mcp.types import ListToolsResult
from rich.console import Console

from mcp_audit.connector import ServerConnector, _list_pages
from mcp_audit.finding_display import finding_views
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ProtocolObservation, ServerAudit, TransportType
from mcp_audit.protocol import ProtocolCapture
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.suppressions import IgnoreEntry, apply_suppressions
from tests.conftest import make_server_config
from tests.fixtures.protocol_server import ProtocolServer


def _http_peer(monkeypatch: pytest.MonkeyPatch, mode: str) -> ProtocolServer:
    server = ProtocolServer(mode)

    def handle(request: httpx2.Request) -> httpx2.Response:
        if request.method != "POST":
            return httpx2.Response(405)
        response = server.respond(json.loads(request.content))
        headers = {"Mcp-Session-Id": "synthetic-session-marker"} if mode == "minting" else {}
        return httpx2.Response(200, json=response, headers=headers) if response else httpx2.Response(202)

    def factory() -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))

    monkeypatch.setattr("mcp_audit.connector.create_mcp_http_client", factory)
    return server


async def _connect_http(monkeypatch: pytest.MonkeyPatch, mode: str, *, canary: bool = False) -> ServerAudit:
    _http_peer(monkeypatch, mode)
    config = make_server_config(
        name="protocol-fixture",
        transport=TransportType.HTTP,
        command=None,
        url="https://protocol.example.test/mcp",
    )
    return await ServerConnector(timeout=5).connect(config, canary_calls=1 if canary else 0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mode,rules",
    [
        ("modern", []),
        ("legacy", ["MCP044"]),
        ("minting", ["MCP045"]),
        ("no-hints", ["MCP047"]),
        ("logging", ["MCP046"]),
        ("scope-mismatch", ["MCP048"]),
        ("invalid-ttl", ["MCP049"]),
        ("invalid-ttl-secret", ["MCP049"]),
        ("legacy-no-hints", ["MCP044"]),
    ],
)
async def test_protocol_fixture_exact_rules(
    monkeypatch: pytest.MonkeyPatch, mode: str, rules: list[str]
) -> None:
    audit = await _connect_http(monkeypatch, mode)
    assert audit.connection_status == (
        "partial" if mode in {"no-hints", "invalid-ttl-secret"} else "connected"
    )
    assert [f.rule_id for f in audit.protocol_findings] == rules
    assert audit.protocol is not None
    assert audit.protocol.era == ("legacy" if mode.startswith("legacy") else "modern")
    assert audit.protocol.discover_supported == (False if mode.startswith("legacy") else True)
    assert audit.protocol.extensions == ["io.modelcontextprotocol/tasks"]
    assert audit.protocol.server_info == {"name": "synthetic-protocol", "version": "1"}
    assert audit.protocol.session_id_minted is (mode == "minting")
    wire = audit.model_dump_json()
    assert "synthetic-session-marker" not in wire
    assert "synthetic-validation-marker" not in wire
    if mode == "no-hints":
        hints = [hint for hint in audit.protocol.cache_hints if hint.method == "tools/list"]
        assert len(hints) == 1 and hints[0].ttl_ms is None and hints[0].cache_scope is None
    if mode == "invalid-ttl":
        hints = [hint for hint in audit.protocol.cache_hints if hint.method == "tools/list"]
        assert len(hints) == 1 and hints[0].ttl_ms == -1 and hints[0].ttl_ms_present
    if mode in {"no-hints", "scope-mismatch", "invalid-ttl", "invalid-ttl-secret"}:
        assert audit.protocol_findings[0].requirement_level == "protocol_must"


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["modern", "no-hints", "invalid-ttl"])
async def test_stdio_observations(mode: str) -> None:
    config = make_server_config(
        command=sys.executable, args=["-I", str(Path(__file__).parent / "fixtures/protocol_server.py"), mode]
    )
    audit = await ServerConnector(timeout=5).connect(config)
    assert audit.connection_status == ("partial" if mode == "no-hints" else "connected")
    assert audit.protocol is not None and audit.protocol.era == "modern"
    assert audit.protocol.session_id_minted is None
    assert [f.rule_id for f in audit.protocol_findings] == (
        {"no-hints": ["MCP047"], "invalid-ttl": ["MCP049"]}.get(mode, [])
    )


@pytest.mark.anyio
async def test_canary_order_is_low_and_not_membership_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = await _connect_http(monkeypatch, "order", canary=True)
    assert audit.connection_status == "connected"
    assert [f.rule_id for f in audit.protocol_findings] == ["MCP050"]
    assert audit.protocol_findings[0].severity == "low"
    assert audit.protocol_findings[0].requirement_level == "protocol_should"
    assert audit.drift_findings == []
    assert audit.protocol is not None
    assert audit.protocol.tools_order == [["status", "health"], ["health", "status"]]


@pytest.mark.anyio
async def test_modern_tool_membership_drift_cites_must(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = await _connect_http(monkeypatch, "change", canary=True)
    assert audit.connection_status == "connected"
    assert audit.protocol_findings == []
    assert len(audit.drift_findings) == 1
    finding = audit.drift_findings[0]
    assert finding.tool_name == "ready" and finding.requirement_level == "protocol_must"
    assert "SEP-2567" in finding.summary


@pytest.mark.anyio
async def test_failed_listing_is_not_missing_hint_or_order_evidence() -> None:
    capture = ProtocolCapture(ProtocolObservation(era="modern"))

    async def fetch(**kwargs: object) -> ListToolsResult:
        if kwargs.get("cursor"):
            raise RuntimeError("Synthetic page failure")
        return ListToolsResult(tools=[], next_cursor="second")

    with pytest.raises(RuntimeError, match="Synthetic page failure"):
        await _list_pages(fetch, lambda page: page.tools, capture=capture, method="tools/list")
    assert capture.observation.cache_hints == []
    assert capture.observation.tools_order == []
    assert capture.findings == []


@pytest.mark.anyio
async def test_missing_session_evidence_emits_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = await _connect_http(monkeypatch, "missing-evidence")
    assert audit.connection_status == "failed"
    assert audit.protocol_findings == []
    capture = ProtocolCapture(ProtocolObservation())
    capture.session_rules(TransportType.HTTP)
    assert capture.findings == []


@pytest.mark.anyio
async def test_protocol_findings_reach_reports_and_suppression(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = await _connect_http(monkeypatch, "no-hints")
    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="fixture",
        os_platform="fixture",
        servers_failed=0,
        total_tools=len(audit.tools),
        high_risk_servers=0,
        servers_discovered=1,
        servers_connected=1,
        audits=[audit],
        scan_duration_seconds=0,
    )
    assert [view.rule_id for view in finding_views(report)] == ["MCP047"]
    assert report.ensure_review_summary().action_count == 1
    assert "MCP047" in HtmlReportGenerator().generate(report)
    output = StringIO()
    ReportGenerator(Console(file=output)).render_terminal(report, details=True)
    assert "MCP047" in output.getvalue()
    sarif = SarifGenerator().generate(report)
    results = sarif["runs"][0]["results"]
    assert [(result["ruleId"], result["level"]) for result in results] == [("MCP047", "note")]
    assert results[0]["properties"]["requirement_level"] == "protocol_must"
    assert "MCP047" in {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    loaded = AuditReport.model_validate_json(report.model_dump_json())
    assert loaded.audits[0].protocol == audit.protocol
    apply_suppressions(
        report,
        [IgnoreEntry(rule="MCP047", server="protocol-fixture", tool="*", reason="Synthetic exception")],
    )
    assert len(report.suppressed) == 1


def test_session_id_transport_log_is_redacted() -> None:
    from mcp_audit.connector import _SseLogFilter

    record = logging.LogRecord(
        "mcp.client.streamable_http",
        logging.INFO,
        "fixture",
        1,
        "Received session ID: %s",
        ("synthetic-session-marker",),
        None,
    )
    assert _SseLogFilter().filter(record)
    assert record.getMessage() == "Received session ID: <redacted>"


@pytest.mark.anyio
async def test_absent_hints_from_failed_rpc_are_not_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _http_peer(monkeypatch, "missing-evidence")
    config = make_server_config(
        transport=TransportType.HTTP, command=None, url="https://protocol.example.test/mcp"
    )
    audit = await ServerConnector(timeout=5).connect(config)
    assert audit.connection_status == "failed"
    assert audit.protocol_findings == []
    assert "tools/call" not in server.methods
