"""Deadline exhaustion must discard incomplete per-server analysis evidence."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import FrameType

import pytest

from mcp_audit.analysis_budget import AnalysisTimeout, analysis_budget
from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import PermissionCategory, PermissionFinding, ServerAudit, ServerConfig, ToolInfo
from tests.conftest import make_server_config


def test_deadline_interrupts_python_work_and_restores_trace() -> None:
    previous = sys.gettrace()
    started = time.monotonic()
    with pytest.raises(AnalysisTimeout), analysis_budget(started + 0.02):
        while True:
            time.monotonic()
    assert sys.gettrace() is previous


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


@pytest.mark.anyio
@pytest.mark.parametrize("verification", ["verify_artifacts", "download_artifacts"])
async def test_slow_optional_artifact_verification_preserves_completed_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verification: str
) -> None:
    from mcp_audit import pinning
    from mcp_audit.pkgverify import ArtifactResult, PackageRef, RegistryClient

    server = make_server_config(name="slow-verification", args=["fixture-pkg@1.0.0"])
    tool = ToolInfo.model_validate({"name": "execute_command", "description": "Run shell commands"})
    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    store.pin_server(
        server.name,
        [],
        server_config=server,
        package_hashes={"npm:fixture-pkg:1.0.0": "sha512-fixture"},
        artifact_hashes={"npm:fixture-pkg:1.0.0": "fixture.tgz=fixture-digest"},
    )
    monkeypatch.setattr(pinning, "PinStore", lambda: store)

    async def connect(_self: ServerConnector, config: ServerConfig) -> ServerAudit:
        assert config is server
        return ServerAudit(server=server, connection_status="connected", tools=[tool])

    monkeypatch.setattr(ServerConnector, "connect", connect)

    def slow_hash(_self: RegistryClient, _ref: PackageRef) -> str:
        time.sleep(1.1)
        return "sha512-fixture"

    def slow_artifact(_self: RegistryClient, _ref: PackageRef) -> ArtifactResult:
        time.sleep(1.1)
        return ArtifactResult({"fixture.tgz": "fixture-digest"}, True)

    if verification == "verify_artifacts":
        monkeypatch.setattr(RegistryClient, "fetch_hash", slow_hash)
    else:
        monkeypatch.setattr(RegistryClient, "fetch_artifact", slow_artifact)

    report = await run_scan(
        ScanOptions(
            timeout=1,
            verify_artifacts=verification == "verify_artifacts",
            download_artifacts=verification == "download_artifacts",
        ),
        servers=[server],
    )

    audit = report.audits[0]
    assert audit.connection_status == "connected"
    assert any(f.category == PermissionCategory.SHELL_EXEC for f in audit.permissions)
    assert not any(w.code == "analysis_timeout" for w in report.warnings)
    assert report.coverage["permissions"].state == "complete"
