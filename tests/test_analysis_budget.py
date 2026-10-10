"""Deadline exhaustion must discard incomplete per-server analysis evidence."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import FrameType

import pytest

from mcp_audit.analysis_budget import AnalysisTimeout, analysis_budget
from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import PermissionFinding, ToolInfo
from tests.conftest import make_server_config


def test_deadline_interrupts_python_work_and_restores_trace() -> None:
    previous = sys.gettrace()
    started = time.monotonic()
    with pytest.raises(AnalysisTimeout), analysis_budget(started + 0.02):
        while True:
            time.monotonic()
    assert sys.gettrace() is previous
    assert time.monotonic() - started < 1


def test_deadline_restores_an_existing_tracer() -> None:
    def previous_trace(frame: FrameType, event: str, arg: object) -> None:
        return None

    original = sys.gettrace()
    sys.settrace(previous_trace)
    try:
        with pytest.raises(AnalysisTimeout), analysis_budget(time.monotonic() + 0.02):
            while True:
                time.monotonic()
        assert sys.gettrace() is previous_trace
    finally:
        sys.settrace(original)


@pytest.mark.anyio
async def test_fixture_analysis_uses_remaining_server_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "bounded_surface_server.py"
    server = make_server_config(command=sys.executable, args=[str(fixture), "tools", "10"])

    def slow_analysis(
        self: PermissionAnalyzer,
        tools: list[ToolInfo],
        *,
        incomplete_reasons: list[str] | None = None,
    ) -> list[PermissionFinding]:
        assert len(tools) == 1  # A real fixture listing reached analysis.
        while True:
            time.monotonic()

    monkeypatch.setattr(PermissionAnalyzer, "analyze_server", slow_analysis)
    started = time.monotonic()
    report = await run_scan(ScanOptions(config_only=True, timeout=1), servers=[server])
    assert time.monotonic() - started < 1 + 4.5
    assert report.audits[0].connection_status == "timeout"
    assert not report.audits[0].permissions
    assert any(w.code == "analysis_timeout" and w.servers == [server.name] for w in report.warnings)
    assert report.coverage["permissions"].state != "complete"
