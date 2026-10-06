"""Additive canary coverage and rendering contract, using local fixtures only."""

from __future__ import annotations

import io
import json
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from mcp.types import Implementation
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, TransportType
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

FIXTURE = str(Path(__file__).parent / "fixtures" / "deadbugz_server.py")
NOT_EXCLUDED = [
    "time",
    "randomness",
    "call_count_gt_budget",
    "client_identity",
    "arguments",
    "other_tool_sequences",
    "later_sessions",
]
REPORTS = Path("tests/fixtures/reports")


def _terminal(report: AuditReport) -> str:
    output = io.StringIO()
    ReportGenerator(Console(file=output, width=200, highlight=False)).render_terminal(report)
    return output.getvalue()


def _validate(payload: object) -> None:
    schema = json.loads(Path("examples/schemas/audit-report.schema.json").read_text())
    Draft202012Validator(schema).validate(payload)


@pytest.mark.anyio
async def test_clean_canary_json_contract() -> None:
    config = make_server_config(command=sys.executable, args=[FIXTURE, "clean"])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    payload = json.loads(report.model_dump_json())
    summary = payload["audits"][0]["canary"]
    assert summary["status"] == "complete"
    assert summary["warnings"] == []
    assert summary["not_excluded"] == NOT_EXCLUDED
    assert summary["client_identity"] == f"mcp-audit/{__version__}"
    assert summary["elapsed_seconds"] > 0
    assert summary["call_budget"] == summary["requested_calls"] == 5
    _validate(payload)
    assert "Canary test-server: complete, 5/5 calls" in _terminal(report)
    assert "Not ruled out:" in HtmlReportGenerator().generate(report)
    sarif = SarifGenerator().generate(report)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["mcpAuditCanary"][0]["not_excluded"] == NOT_EXCLUDED


@pytest.mark.anyio
@pytest.mark.parametrize("calls", [0, 2])
async def test_fixture_observes_presented_identity(calls: int) -> None:
    config = make_server_config(command=sys.executable, args=[FIXTURE, "identity"])
    audit = await ServerConnector(timeout=15).connect(config, canary_calls=calls)
    assert audit.connection_status == "connected"
    assert audit.tools[0].description is not None
    assert json.loads(audit.tools[0].description) == {"name": "mcp-audit", "version": __version__}


@pytest.mark.anyio
@pytest.mark.parametrize("transport", list(TransportType))
@pytest.mark.parametrize("calls", [0, 2])
async def test_every_transport_presents_identity(
    monkeypatch: pytest.MonkeyPatch, transport: TransportType, calls: int
) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, server: object, **kwargs: object) -> None:
            captured.update(kwargs)
            raise RuntimeError("fixture stops before connecting")

    monkeypatch.setattr("mcp_audit.connector.Client", FakeClient)
    config = make_server_config(transport=transport, url="http://127.0.0.1:1/mcp")
    audit = await ServerConnector().connect(config, canary_calls=calls)
    assert audit.connection_status == "failed"
    identity = captured["client_info"]
    assert isinstance(identity, Implementation)
    assert identity.name == "mcp-audit"
    assert identity.version == __version__
    if calls:
        assert audit.canary is not None and audit.canary.elapsed_seconds is not None


def test_legacy_canary_validates_and_renders() -> None:
    payload = json.loads((REPORTS / "legacy_canary_report.json").read_text())
    assert not {"client_identity", "elapsed_seconds", "call_budget", "not_excluded"} & set(
        payload["audits"][0]["canary"]
    )
    _validate(payload)
    report = AuditReport.model_validate(payload)
    summary = report.audits[0].canary
    assert summary is not None
    assert summary.call_budget == summary.requested_calls == 5
    assert summary.client_identity == "" and summary.elapsed_seconds is None
    assert summary.not_excluded == NOT_EXCLUDED
    assert "Not ruled out:" in _terminal(report)
    assert "Not ruled out:" in HtmlReportGenerator().generate(report)
    assert SarifGenerator().generate(report)["runs"][0]["invocations"]


def test_canary_render_snapshot_and_non_canary_unchanged() -> None:
    expected = json.loads((REPORTS / "canary_render_snapshot.json").read_text())
    report = AuditReport.model_validate_json((REPORTS / "legacy_canary_report.json").read_text())
    terminal = _terminal(report)
    html = HtmlReportGenerator().generate(report)
    assert [line for line in terminal.splitlines() if line.startswith(("Canary ", "Not ruled out:"))] == (
        expected["canary"]["terminal"]
    )
    assert expected["canary"]["html"] in html
    assert SarifGenerator().generate(report)["runs"][0]["invocations"] == expected["canary"]["sarif"]
    report.audits[0].canary = None
    sarif = SarifGenerator().generate(report)
    sarif["runs"][0]["tool"]["driver"]["version"] = "<package-version>"
    outputs = {
        "terminal": _terminal(report),
        "html": HtmlReportGenerator().generate(report),
        "sarif": json.dumps(sarif, sort_keys=True),
    }
    assert {key: sha256(value.encode()).hexdigest() for key, value in outputs.items()} == (
        expected["non_canary_sha256"]
    )


def test_canary_renderers_escape_untrusted_identifiers() -> None:
    report = AuditReport.model_validate_json((REPORTS / "legacy_canary_report.json").read_text())
    audit = report.audits[0]
    audit.server.name = "[bold]fixture[/bold]\x1b[2J"
    assert audit.canary is not None
    audit.canary.not_excluded.append("<script>\x1b[2J[bold]unknown[/bold]")
    terminal = _terminal(report)
    html = HtmlReportGenerator().generate(report)
    assert "[bold]fixture[/bold]" in terminal and "[bold]unknown[/bold]" in terminal
    assert "\x1b" not in terminal + html
    assert "<script>" not in html and "&lt;script&gt;" in html
