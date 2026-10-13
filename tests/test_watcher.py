"""Tests for watch-mode helpers — path discovery, diff rendering, output writing."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import threading
import types
import warnings
from collections.abc import AsyncIterator
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
        monkeypatch.setattr(
            watcher,
            "discover_all_configs",
            lambda clients, parse_errors=None, config_paths=None: servers,
        )

        assert watcher._get_watch_paths() == [existing]

    def test_empty_when_nothing_discovered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            watcher, "discover_all_configs", lambda clients, parse_errors=None, config_paths=None: []
        )
        assert watcher._get_watch_paths() == []

    def test_includes_explicit_config_without_discovered_servers(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        explicit = tmp_path / "explicit.json"
        explicit.write_text("{}")
        monkeypatch.setattr(
            watcher, "discover_all_configs", lambda clients, parse_errors=None, config_paths=None: []
        )
        assert watcher._get_watch_paths([], explicit) == [explicit]

    def test_passes_client_filter_to_discovery(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        config = tmp_path / "cursor.json"
        config.write_text("{}")
        seen: list[object] = []

        def discover(
            clients: object, parse_errors: object = None, config_paths: list[Path] | None = None
        ) -> list[object]:
            seen.append(clients)
            return [make_server_config().model_copy(update={"config_path": str(config)})]

        monkeypatch.setattr(watcher, "discover_all_configs", discover)
        watcher._get_watch_paths([make_server_config().client])
        assert seen == [[make_server_config().client]]


class TestWatchClientFilter:
    def test_uses_core_parser_without_deprecated_cli_shim(self) -> None:
        import inspect
        import re

        source = inspect.getsource(watcher)
        assert re.search(r"mcp_audit\.cli\b", source) is None
        assert "from mcp_audit.client_filter import _parse_clients" in source
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            from mcp_audit.client_filter import _parse_clients

            assert _parse_clients("cursor") is not None


class TestRenderDiff:
    def test_reports_added_and_removed_servers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = _capture_console(monkeypatch)
        watcher._render_diff(_report([_audit("old")]), _report([_audit("new")]))
        out = buf.getvalue()
        assert "+ claude_code:workstation:new" in out
        assert "- claude_code:workstation:old" in out

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

    def test_same_server_name_in_different_clients_is_distinct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buf = _capture_console(monkeypatch)
        old = _audit("same").model_copy(update={"server": make_server_config(name="same")})
        from mcp_audit.models import ClientType

        cursor = make_server_config(name="same", client=ClientType.CURSOR)
        new = _audit("same").model_copy(update={"server": cursor})
        watcher._render_diff(_report([old]), _report([new]))
        assert "- claude_code:workstation:same" in buf.getvalue()
        assert "+ cursor:workstation:same" in buf.getvalue()


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

    def test_watch_writer_writes_through_symlinks(self, tmp_path: Path) -> None:
        target = tmp_path / "target.txt"
        target.write_text("old", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        watcher._atomic_write_text(link, "new")
        assert link.is_symlink()
        assert target.read_text(encoding="utf-8") == "new"

    def test_watch_writer_preserves_existing_file_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        path.write_text("old", encoding="utf-8")
        path.chmod(0o640)
        watcher._atomic_write_text(path, "new")
        assert stat.S_IMODE(path.stat().st_mode) == 0o640

    def test_watch_writer_writes_directly_to_fifo(self, tmp_path: Path) -> None:
        fifo = tmp_path / "output.fifo"
        os.mkfifo(fifo)
        received: list[str] = []

        def read_fifo() -> None:
            with fifo.open(encoding="utf-8") as source:
                received.append(source.read())

        reader = threading.Thread(target=read_fifo)
        reader.start()
        watcher._atomic_write_text(fifo, "watch report")
        reader.join(timeout=2)
        assert not reader.is_alive()
        assert received == ["watch report"]

    @pytest.mark.anyio
    async def test_watch_rejects_output_targeting_malformed_discovered_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        malformed = tmp_path / "malformed.json"
        malformed.write_text("{", encoding="utf-8")

        def discover(
            clients: object,
            parse_errors: object = None,
            config_paths: list[Path] | None = None,
        ) -> list[object]:
            assert config_paths is not None
            config_paths.append(malformed)
            return []

        async def changes(*paths: str) -> AsyncIterator[set[tuple[int, str]]]:
            yield set()

        monkeypatch.setattr(watcher, "discover_all_configs", discover)
        monkeypatch.setitem(sys.modules, "watchfiles", types.SimpleNamespace(awatch=changes))
        with pytest.raises(SystemExit, match="2"):
            await watcher._watch_loop(str(malformed), None, True, None, 10, False, None, "/dev/null")
        assert malformed.read_text(encoding="utf-8") == "{"
