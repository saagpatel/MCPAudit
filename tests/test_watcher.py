"""Tests for watch-mode helpers — path discovery, diff rendering, output writing."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.console import Console

from mcp_audit import watcher
from mcp_audit.models import AuditReport, RiskScore, ServerAudit
from tests.conftest import make_server_config


def _report(audits: list[ServerAudit]) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="testhost",
        os_platform="Darwin",
        servers_discovered=len(audits),
        servers_connected=0,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=audits,
        scan_duration_seconds=0.1,
    )


def _audit(name: str, composite: float | None = None) -> ServerAudit:
    risk = (
        RiskScore(
            composite=composite,
            file_access=0.0,
            network_access=0.0,
            shell_execution=0.0,
            destructive=0.0,
            exfiltration=0.0,
        )
        if composite is not None
        else None
    )
    return ServerAudit(server=make_server_config(name=name), connection_status="skipped", risk_score=risk)


def _capture_console(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    buf = io.StringIO()
    monkeypatch.setattr(
        watcher, "_console", Console(file=buf, force_terminal=False, width=120, highlight=False)
    )
    return buf


class TestGetWatchPaths:
    def test_dedupes_and_drops_missing_paths(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        existing = tmp_path / "config.json"
        existing.write_text("{}")
        missing = tmp_path / "gone.json"
        servers = [
            make_server_config(name="a").model_copy(update={"config_path": str(existing)}),
            make_server_config(name="b").model_copy(update={"config_path": str(existing)}),
            make_server_config(name="c").model_copy(update={"config_path": str(missing)}),
        ]
        monkeypatch.setattr(watcher, "discover_all_configs", lambda clients, parse_errors=None: servers)

        assert watcher._get_watch_paths() == [existing]

    def test_empty_when_nothing_discovered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(watcher, "discover_all_configs", lambda clients, parse_errors=None: [])
        assert watcher._get_watch_paths() == []


class TestRenderDiff:
    def test_reports_added_and_removed_servers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = _capture_console(monkeypatch)
        watcher._render_diff(_report([_audit("old")]), _report([_audit("new")]))
        out = buf.getvalue()
        assert "+ new" in out
        assert "- old" in out

    def test_reports_significant_risk_delta_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = _capture_console(monkeypatch)
        prev = _report([_audit("jumpy", composite=2.0), _audit("steady", composite=2.0)])
        curr = _report([_audit("jumpy", composite=4.5), _audit("steady", composite=2.2)])
        watcher._render_diff(prev, curr)
        out = buf.getvalue()
        assert "jumpy: 2.0" in out and "4.5" in out
        assert "steady" not in out  # 0.2 delta is below the 0.5 threshold

    def test_missing_risk_scores_do_not_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = _capture_console(monkeypatch)
        watcher._render_diff(_report([_audit("srv")]), _report([_audit("srv")]))
        assert buf.getvalue() == ""


class TestWriteOutputs:
    def test_writes_json_and_sarif_when_configured(self, tmp_path: Path) -> None:
        report = _report([_audit("srv", composite=1.0)])
        json_path = tmp_path / "out.json"
        sarif_path = tmp_path / "out.sarif"

        watcher._write_outputs(report, str(json_path), str(sarif_path))

        assert json.loads(json_path.read_text())["audits"][0]["server"]["name"] == "srv"
        sarif = json.loads(sarif_path.read_text())
        assert sarif["version"] == "2.1.0"

    def test_writes_nothing_when_paths_unset(self, tmp_path: Path) -> None:
        watcher._write_outputs(_report([]), None, None)
        assert list(tmp_path.iterdir()) == []
