"""Tests for the public scan engine (mcp_audit.engine).

Covers the contract the CLI, MCP server, api.py, and downstream packages
(mcp-trust, shadow-mcp) rely on: ScanOptions defaults, silence-by-default
output discipline, the AuditReport schema_version marker, and the deprecated
cli._run_scan_core compatibility shim.
"""

from __future__ import annotations

import io
from pathlib import Path

import anyio
import pytest
from rich.console import Console

from mcp_audit import engine
from mcp_audit.discovery import ConfigParseError
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AUDIT_REPORT_SCHEMA_VERSION, ClientType, ServerConfig
from tests.conftest import make_server_config


def test_scan_options_defaults_mirror_flagless_scan() -> None:
    options = ScanOptions()
    assert options.skip_connect is False
    assert options.config_only is False
    assert options.timeout == 10
    assert not any(
        getattr(options, flag)
        for flag in (
            "inject_check",
            "ssrf_check",
            "egress_check",
            "pin_check",
            "trifecta_check",
            "shadow_check",
            "escalation_check",
            "provenance_check",
            "integrity_check",
            "verify_artifacts",
            "download_artifacts",
            "llm_analysis",
        )
    )


def test_run_scan_is_silent_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Library/MCP callers get no stdout chatter — stdout may carry MCP stdio frames."""
    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )
    # llm_analysis without an API key prints an advisory warning on the CLI path;
    # with no console passed, it must stay silent.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    report = anyio.run(run_scan, ScanOptions(skip_connect=True, llm_analysis=True))

    assert report.servers_discovered == 1
    captured = capsys.readouterr()
    assert captured.out == ""


def test_run_scan_prints_warnings_to_provided_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False)

    async def _scan() -> None:
        await run_scan(ScanOptions(skip_connect=True, llm_analysis=True), console=console)

    anyio.run(_scan)

    assert "--llm-analysis" in buffer.getvalue()


def test_report_carries_schema_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )

    report = anyio.run(run_scan, ScanOptions(skip_connect=True))

    assert report.schema_version == AUDIT_REPORT_SCHEMA_VERSION == 1
    assert report.model_dump(mode="json")["schema_version"] == 1


def test_run_scan_raises_on_missing_extra_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo'd extra_config path must fail loudly, never degrade to an empty clean report."""
    monkeypatch.setattr(engine, "discover_all_configs", lambda clients, parse_errors=None: [])

    async def _scan() -> None:
        await run_scan(ScanOptions(skip_connect=True, config_only=True, extra_config="/nope/missing.json"))

    with pytest.raises(ValueError, match="not found"):
        anyio.run(_scan)


def test_run_scan_raises_on_unparseable_extra_config(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")

    async def _scan() -> None:
        await run_scan(ScanOptions(skip_connect=True, config_only=True, extra_config=str(bad)))

    with pytest.raises(ValueError, match="Failed to parse"):
        anyio.run(_scan)


def test_skipped_check_surfaces_as_structured_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """A silently-skipped check must be visible in report data, not just on the console."""
    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    report = anyio.run(run_scan, ScanOptions(skip_connect=True, llm_analysis=True))

    [warning] = [w for w in report.warnings if w.check == "llm_analysis"]
    assert warning.code == "missing_credential"
    assert warning.servers == []
    assert "[yellow]" not in warning.message  # plain text, no console markup
    assert report.model_dump(mode="json")["warnings"][0]["code"] == "missing_credential"


def test_ignored_option_surfaces_as_structured_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "discover_all_configs", lambda clients, parse_errors=None: [])

    report = anyio.run(run_scan, ScanOptions(skip_connect=True, ssrf_allowlist="internal.example"))

    [warning] = [w for w in report.warnings if w.code == "option_ignored"]
    assert warning.check == "ssrf_check"


def test_clean_scan_reports_no_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )

    report = anyio.run(run_scan, ScanOptions(skip_connect=True))

    assert report.warnings == []


def test_missing_pin_baseline_surfaces_as_structured_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pin-comparison checks with nothing pinned emit one warning per requested check."""
    from mcp_audit import pinning

    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )
    real_pin_store = pinning.PinStore
    monkeypatch.setattr(pinning, "PinStore", lambda: real_pin_store(path=tmp_path / "pins.yaml"))

    report = anyio.run(run_scan, ScanOptions(skip_connect=True, escalation_check=True, integrity_check=True))

    warnings = {w.check: w for w in report.warnings}
    assert set(warnings) == {"escalation_check", "integrity_check"}
    assert all(w.code == "pin_baseline_missing" for w in warnings.values())
    assert "--escalation-check: no pin baseline found" in warnings["escalation_check"].message


def test_stale_pin_baseline_names_affected_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pinned server whose baseline predates the check's capture is named in the warning."""
    from mcp_audit import pinning

    class _StalePinStore:
        def pinned_servers(self) -> list[str]:
            return ["srv"]

        def baseline_config(self, name: str) -> None:
            return None

        def baseline_tools(self, name: str) -> None:
            return None

        def baseline_artifacts(self, name: str) -> None:
            return None

        def baseline_package_hashes(self, name: str) -> None:
            return None

        def baseline_artifact_hashes(self, name: str) -> None:
            return None

        def check_drift(self, name: str, tools: object) -> list[object]:
            return []

    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )
    monkeypatch.setattr(pinning, "PinStore", lambda: _StalePinStore())

    report = anyio.run(run_scan, ScanOptions(skip_connect=True, provenance_check=True))

    [warning] = report.warnings
    assert warning.code == "pin_baseline_stale"
    assert warning.check == "provenance_check"
    assert warning.servers == ["srv"]
    assert "srv" in warning.message


def test_schema_version_pins_top_level_field_set() -> None:
    """Couples schema_version to the AuditReport field set.

    If this test fails because you REMOVED, RENAMED, or RETYPED a field, bump
    AUDIT_REPORT_SCHEMA_VERSION and update docs/OUTPUT-CONTRACT.md. If you only
    ADDED a field, extend this set — additive changes do not bump the version.
    """
    from mcp_audit.models import AuditReport

    assert AUDIT_REPORT_SCHEMA_VERSION == 1
    assert set(AuditReport.model_fields) == {
        "schema_version",
        "scan_timestamp",
        "hostname",
        "os_platform",
        "servers_discovered",
        "servers_connected",
        "servers_failed",
        "total_tools",
        "high_risk_servers",
        "audits",
        "scan_duration_seconds",
        "config_health_findings",
        "policy_result",
        "fleet_trifecta_findings",
        "shadowing_findings",
        "warnings",
    }


def test_cli_run_scan_core_shim_warns_and_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    """The old private entry point still works (shadow-mcp compat) but warns."""
    from functools import partial

    from mcp_audit import cli
    from mcp_audit.overrides import OverrideApplier, OverrideConfig

    monkeypatch.setattr(
        engine, "discover_all_configs", lambda clients, parse_errors=None: [make_server_config(name="srv")]
    )

    with pytest.warns(DeprecationWarning, match="mcp_audit.engine.run_scan"):
        report = anyio.run(
            partial(cli._run_scan_core, True, None, 10, None, OverrideApplier(OverrideConfig()))
        )

    assert [audit.server.name for audit in report.audits] == ["srv"]


async def test_run_scan_surfaces_discovery_parse_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_discover(
        clients: list[ClientType] | None = None,
        parse_errors: list[ConfigParseError] | None = None,
    ) -> list[ServerConfig]:
        if parse_errors is not None:
            parse_errors.append(
                ConfigParseError(path="/tmp/broken.json", client=ClientType.CURSOR, reason="boom")
            )
        return []

    monkeypatch.setattr(engine, "discover_all_configs", fake_discover)
    report = await run_scan(ScanOptions(skip_connect=True))
    failures = [
        finding for finding in report.config_health_findings if finding.finding_type == "config_parse_failure"
    ]
    assert len(failures) == 1
    assert "/tmp/broken.json" in failures[0].summary


async def test_one_failing_server_does_not_kill_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """A per-server analysis crash becomes a failed audit, not a dead fleet scan."""
    boom = make_server_config(name="boom")
    ok = make_server_config(name="ok")
    monkeypatch.setattr(engine, "discover_all_configs", lambda clients, parse_errors=None: [boom, ok])

    from mcp_audit.connector import ServerConnector

    real_skip = ServerConnector.skip_connect_audit

    def exploding(self: object, srv: ServerConfig) -> object:
        if srv.name == "boom":
            raise RuntimeError("kaboom")
        return real_skip(self, srv)  # type: ignore[arg-type]

    monkeypatch.setattr(ServerConnector, "skip_connect_audit", exploding)

    report = await run_scan(ScanOptions(skip_connect=True))

    by_name = {audit.server.name: audit for audit in report.audits}
    assert set(by_name) == {"boom", "ok"}
    assert by_name["boom"].connection_status == "failed"
    assert "kaboom" in (by_name["boom"].connection_error or "")
    assert by_name["ok"].connection_status == "skipped"
