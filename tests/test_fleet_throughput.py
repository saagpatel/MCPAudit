"""P-1 output compatibility and bounded per-server CPU reuse."""

from __future__ import annotations

import hashlib
import io
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic_core import to_json
from rich.console import Console

from mcp_audit import analyzer
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ServerAudit
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_tool

# Captured from the parent revision, using the committed report fixtures and
# fixed terminal width. Changes to performance must preserve all four surfaces.
# X-2 updates only the sample terminal hash for explicit check recheck commands.
GOLDEN = {
    "sample_audit_report": {
        "terminal": "ad77fa92ebb3f7b68cb7e7369648738b0bc50b143c9bbf070c3d2e7378143f38",
        "json": "026339d485f60e1dd5b02bcff7e77b6e3b13ac4fde3dc6ce8666a5874006489b",
        "html": "ac05406211d621963519be1ba3b2a613ae950233031e418281328ad4a7b30df9",
        "sarif": "63b7924e4ccc76c4b8b64df10362a34a6d6767df15dad9fa8c78c6396fe54957",
    },
    "config_only_report": {
        "terminal": "d44e0b3bdc01745fe4c4ef3f809f4353ac183613f8d1367c74a4d3a277145f43",
        "json": "9662889625ed5dcc829d58897a88c17169249c4b39407b80fd208572142df9bc",
        "html": "d6a68006cace935cc6328659c5d30d947c3118b5feb56ed7d40b89c5cf174f0f",
        "sarif": "0636a00191a2afa12cc3e02f219cd05e2fa869cd5af1dc97e8439d06a36cb58c",
    },
}
KEYWORD_GOLDEN = {
    "sample_audit_report": "f777e9ee457669c865c5ca9fc379d87bf1c81d0436e00c846e1e1ff236b0d6d8",
    "config_only_report": "cf1cbb66a638b4860a516671fb74850e6ccf787fe6c4c8d29e9c04efe880bd05",
}


def fixture_report(name: str = "sample_audit_report") -> AuditReport:
    return AuditReport.model_validate_json(Path("tests/fixtures/reports", f"{name}.json").read_text())


@pytest.mark.parametrize("fixture", KEYWORD_GOLDEN)
def test_fixture_permission_analysis_preserves_parent_golden(fixture: str) -> None:
    report = fixture_report(fixture)
    engine = analyzer.PermissionAnalyzer()
    findings = [
        [finding.model_dump(mode="json") for finding in engine.analyze_server(audit.tools)]
        for audit in report.audits
    ]
    assert (
        hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest() == KEYWORD_GOLDEN[fixture]
    )


def _sarif_without_tool_version(report: AuditReport) -> dict[str, Any]:
    # SARIF embeds the installed package version; pin it so the hash tracks rendering only.
    sarif = SarifGenerator().generate(report)
    sarif["runs"][0]["tool"]["driver"]["version"] = "0.0.0"
    return sarif


@pytest.mark.parametrize("fixture", GOLDEN)
def test_report_surfaces_preserve_parent_goldens(tmp_path: Path, fixture: str) -> None:
    report = fixture_report(fixture)
    terminal = io.StringIO()
    renderer = ReportGenerator(Console(file=terminal, width=100, force_terminal=False, no_color=True))
    renderer.render_terminal(report, details=True)
    terminal_text = terminal.getvalue()
    path = tmp_path / "report.json"
    renderer.render_json(report, path)
    outputs = {
        "terminal": terminal_text,
        "json": path.read_text(),
        "html": HtmlReportGenerator().generate(report),
        "sarif": json.dumps(_sarif_without_tool_version(report), sort_keys=True),
    }
    assert {name: hashlib.sha256(value.encode()).hexdigest() for name, value in outputs.items()} == GOLDEN[
        fixture
    ]


@pytest.mark.parametrize("servers", [0, 1, 3])
@pytest.mark.parametrize("surrogate", [False, True])
def test_streamed_json_preserves_whole_document_format(tmp_path: Path, servers: int, surrogate: bool) -> None:
    report = fixture_report()
    report.audits = [report.audits[0].model_copy(deep=True) for _ in range(servers)]
    if surrogate and report.audits:
        report.audits[-1].tools[0].input_schema = {"title": "synthetic\ud800", "const": 1e-7}
    safe = report.redacted()
    payload = safe.model_dump(mode="json")
    expected = (
        json.dumps(payload, indent=2).encode("ascii")
        if surrogate and servers
        else to_json(payload, indent=2, ensure_ascii=True)
    )
    path = tmp_path / "report.json"
    ReportGenerator(Console(file=io.StringIO()))._render_redacted_json(safe, path)
    assert path.read_bytes() == expected.replace(b"\n", os.linesep.encode())


def test_streamed_json_serializes_each_audit_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    safe = fixture_report().redacted()
    expected = to_json(safe.model_dump(mode="json"), indent=2, ensure_ascii=True)
    original = ReportGenerator._encode_audit
    calls: list[ServerAudit] = []

    def encoded(self: ReportGenerator, audit: ServerAudit) -> bytes:
        calls.append(audit)
        return original(self, audit)

    monkeypatch.setattr(ReportGenerator, "_encode_audit", encoded)
    path = tmp_path / "report.json"
    ReportGenerator(Console(file=io.StringIO()))._render_redacted_json(safe, path)
    assert calls == safe.audits
    assert path.read_bytes() == expected.replace(b"\n", os.linesep.encode())


def test_streamed_json_freezes_summary_before_omitting_audits() -> None:
    safe = fixture_report().redacted().model_copy(update={"review_summary": None})
    expected = to_json(safe.model_dump(mode="json"), indent=2, ensure_ascii=True)
    fresh = safe.model_copy(update={"review_summary": None})
    output = io.StringIO()
    ReportGenerator(Console(file=io.StringIO()))._stream_redacted_json(fresh, output)
    assert output.getvalue().encode("ascii") == expected
    assert fresh.review_summary is not None


def test_streamed_json_failure_preserves_existing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    safe = fixture_report().redacted()
    path = tmp_path / "report.json"
    path.write_text("previous report")
    before = set(tmp_path.iterdir())

    def failure(self: ReportGenerator, audit: ServerAudit) -> bytes:
        raise ValueError("synthetic late serialization failure")

    monkeypatch.setattr(ReportGenerator, "_encode_audit", failure)
    with pytest.raises(ValueError, match="synthetic late serialization failure"):
        ReportGenerator(Console(file=io.StringIO()))._render_redacted_json(safe, path)
    assert path.read_text() == "previous report"
    assert set(tmp_path.iterdir()) == before


def test_streamed_json_supports_null_output() -> None:
    report = fixture_report().redacted()
    # Calibration intentionally renders to the null device; it has no writable
    # sibling directory for staging, and large fleets spill the bounded spool.
    report.audits = [report.audits[0].model_copy(deep=True) for _ in range(300)]
    assert len(to_json(report.model_dump(mode="json"), indent=2, ensure_ascii=True)) > 1024 * 1024
    ReportGenerator(Console(file=io.StringIO()))._render_redacted_json(report, Path(os.devnull))


def test_keyword_reuse_preserves_weights_paths_context_and_batch_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = [
        make_tool(
            f"status_{index}",
            description="Read file contents and export to endpoint.",
            input_schema={"properties": {"filePath": {"type": "string", "description": "Read file"}}},
        )
        for index in range(20)
    ]
    engine = analyzer.PermissionAnalyzer()
    expected = [finding.model_dump() for tool in tools for finding in engine.analyze_tool(tool)]
    calls: Counter[str] = Counter()
    original = analyzer._keyword_source

    def counted(text: str) -> analyzer._KeywordSource:
        calls[text] += 1
        return original(text)

    monkeypatch.setattr(analyzer, "_keyword_source", counted)
    for batch in (1, 2):
        actual = engine.analyze_server(tools)
        assert [finding.model_dump() for finding in actual] == expected
        assert calls[tools[0].description or ""] == batch
        assert analyzer._KEYWORD_SOURCE_CACHE.get() is None
    actual[0].evidence.clear()
    assert [finding.model_dump() for finding in engine.analyze_server(tools)] == expected


def test_keyword_cache_does_not_retain_large_text_or_survive_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: Counter[str] = Counter()
    original = analyzer._keyword_source

    def counted(text: str) -> analyzer._KeywordSource:
        calls[text] += 1
        if text == "synthetic-failure":
            raise ValueError("synthetic classifier failure")
        return original(text)

    monkeypatch.setattr(analyzer, "_keyword_source", counted)
    large = "read file " * 120
    engine = analyzer.PermissionAnalyzer()
    engine.analyze_server([make_tool("status", description=large) for _ in range(2)])
    assert calls[large] == 2
    with pytest.raises(ValueError, match="synthetic classifier failure"):
        engine.analyze_server([make_tool("status", description="synthetic-failure")])
    assert analyzer._KEYWORD_SOURCE_CACHE.get() is None
