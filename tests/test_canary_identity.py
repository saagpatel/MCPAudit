"""Differential identities use local fixtures and retain the per-server call bound."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from mcp.types import ListRootsResult
from rich.console import Console

from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector, _canary_roots
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import ToolInfo, TransportType
from mcp_audit.pinning import PinStore
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

FIXTURE = str(Path(__file__).parent / "fixtures" / "identity_canary_server.py")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mode", ["tools", "annotations", "capabilities", "prompts", "prompt_results", "resources"]
)
async def test_identity_conditioned_surface_is_high(mode: str, tmp_path: Path) -> None:
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[FIXTURE, mode, str(trace)])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    audit = report.audits[0]
    assert audit.connection_status == "connected"
    assert audit.canary is not None and audit.canary.status == "complete"
    assert len(audit.canary.client_identities) == 2
    assert audit.canary.completed_calls == 5
    assert len(audit.drift_findings) == 1
    finding = audit.drift_findings[0]
    assert finding.kind == "IDENTITY_CONDITIONED_SURFACE"
    assert finding.source == "session" and finding.severity == "high" and finding.after_call == 0
    assert finding.field_changes and finding.stored_hash != finding.current_hash
    # The second identity must not overwrite the primary inventory or hashes.
    assert audit.tools[0].description == "Status."
    assert audit.canary.baseline_hash == audit.canary.current_hash
    assert not evaluate_policy(report, PolicyConfig(fail_on_severity="high")).passed
    assert not evaluate_policy(report, PolicyConfig(fail_on_drift=True)).passed
    result = next(
        r for r in SarifGenerator().generate(report)["runs"][0]["results"] if r["ruleId"] == "MCP009"
    )
    assert result["ruleId"] == "MCP009" and result["level"] == "error"
    assert result["properties"]["kind"] == finding.kind
    assert finding.kind in result["message"]["text"]
    assert finding.kind in HtmlReportGenerator().generate(report)
    terminal = io.StringIO()
    ReportGenerator(Console(file=terminal, width=200)).render_terminal(report)
    assert finding.kind in terminal.getvalue()
    summary = SarifGenerator().generate(report)["runs"][0]["invocations"][0]["properties"]["mcpAuditCanary"][
        0
    ]
    assert summary["client_identities"] == audit.canary.client_identities


@pytest.mark.anyio
@pytest.mark.parametrize("identities,spawns", [(None, 2), (1, 1), (2, 2)])
async def test_spawns_double_but_exercise_calls_do_not(
    identities: int | None, spawns: int, tmp_path: Path
) -> None:
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[FIXTURE, "stable", str(trace)])
    audit = await ServerConnector(timeout=15).connect(config, canary_calls=5, canary_identities=identities)
    assert audit.connection_status == "connected" and not audit.drift_findings
    assert audit.canary is not None and audit.canary.completed_calls == 5
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    assert sum(e["event"] == "spawn" for e in events) == spawns
    assert sum(e["event"] == "tools/call" for e in events) == 5
    assert sum(e["event"] == "prompts/get" for e in events) == audit.canary.prompt_get_calls == 5 + spawns
    assert all(not e["alternate"] for e in events if e["event"] == "tools/call")
    initializations = [e for e in events if e["event"] == "initialize"]
    if spawns == 2:
        assert initializations[0]["clientInfo"] != initializations[1]["clientInfo"]
        assert initializations[0]["capabilities"] != initializations[1]["capabilities"]
        assert "roots" not in initializations[0]["capabilities"]
        assert initializations[1]["capabilities"] == {"roots": {"listChanged": True}}
    # Probing two chosen identities still cannot rule out all other identities.
    assert "client_identity" in audit.canary.not_excluded
    roots = await _canary_roots(object())
    assert isinstance(roots, ListRootsResult) and roots.roots == []


@pytest.mark.anyio
@pytest.mark.parametrize("transport", [TransportType.HTTP, TransportType.SSE])
@pytest.mark.parametrize("identities,spawns", [(None, 1), (1, 1), (2, 2)])
async def test_remote_identity_policy_with_local_transport(
    transport: TransportType,
    identities: int | None,
    spawns: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Substitute only the transport, keeping the shipped connector/session logic.
    # No HTTP endpoint is contacted by this policy test.
    monkeypatch.setattr(ServerConnector, "_connect_http", ServerConnector._connect_stdio)
    monkeypatch.setattr(ServerConnector, "_connect_sse", ServerConnector._connect_stdio)
    trace = tmp_path / "events.jsonl"
    config = make_server_config(
        transport=transport, command=sys.executable, args=[FIXTURE, "tools", str(trace)]
    )
    audit = await ServerConnector(timeout=15).connect(config, canary_calls=2, canary_identities=identities)
    assert audit.connection_status == "connected"
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    assert sum(e["event"] == "spawn" for e in events) == spawns
    assert sum(e["event"] == "tools/call" for e in events) == 2
    assert bool(audit.drift_findings) == (spawns == 2)


@pytest.mark.anyio
async def test_failed_second_identity_retains_primary_evidence(tmp_path: Path) -> None:
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[FIXTURE, "fail", str(trace)])
    audit = await ServerConnector(timeout=15).connect(config, canary_calls=2)
    assert audit.connection_status == "failed"
    assert audit.canary is not None and audit.canary.status == "partial"
    assert audit.canary.completed_calls == 2 and len(audit.canary.client_identities) == 1
    assert audit.canary.warnings and audit.tools[0].description == "Status."
    assert not audit.drift_findings


@pytest.mark.anyio
@pytest.mark.parametrize("signed", [False, True], ids=["unsigned", "signed"])
async def test_saved_v2_pin_detects_already_flipped_call_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed: bool
) -> None:
    from mcp_audit.pin_signing import generate_keypair

    if signed:
        trusted = tmp_path / "trusted.json"
        key = generate_keypair(tmp_path / "keys", trusted)
        store = PinStore(tmp_path / "pins.yaml", signing_key=key.private_key_path, trusted_keys_path=trusted)
    else:
        store = PinStore(tmp_path / "pins.yaml")
    monkeypatch.setattr("mcp_audit.pinning.PinStore", lambda: store)
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[FIXTURE, "stable", str(trace)])
    baseline = await ServerConnector(timeout=15).connect(config)
    assert baseline.connection_status == "connected"
    store.pin_server(config.name, baseline.tools)
    before = store.path.read_bytes()
    config.args[1] = "flipped"
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    audit = report.audits[0]
    assert audit.pin_verification is not None
    assert audit.pin_verification.state == ("verified" if signed else "unsigned")
    assert audit.canary is not None and audit.canary.baseline_source == "pin"
    assert audit.canary.completed_calls == 5 and audit.canary.status == "complete"
    assert audit.canary.baseline_hash != audit.canary.current_hash
    assert len(audit.drift_findings) == 1
    finding = audit.drift_findings[0]
    assert finding.severity == "high" and finding.after_call == 0 and finding.kind is None
    assert finding.surface == "tools" and finding.field_changes[0].path == "/description"
    assert not evaluate_policy(report, PolicyConfig(fail_on_severity="high")).passed
    assert store.path.read_bytes() == before


@pytest.mark.anyio
async def test_unchanged_v2_pin_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = PinStore(tmp_path / "pins.yaml")
    monkeypatch.setattr("mcp_audit.pinning.PinStore", lambda: store)
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[FIXTURE, "stable", str(trace)])
    baseline = await ServerConnector(timeout=15).connect(config)
    store.pin_server(config.name, baseline.tools)
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    audit = report.audits[0]
    assert audit.canary is not None and audit.canary.baseline_source == "pin"
    assert audit.canary.baseline_hash == audit.canary.current_hash
    assert not audit.drift_findings
    assert [warning.code for warning in report.warnings] == ["pin_unsigned"]


def test_legacy_pins_are_not_used_as_v2_canary_baselines(tmp_path: Path) -> None:
    path = tmp_path / "pins.yaml"
    path.write_text(
        "servers:\n  fixture:\n    tools:\n      status:\n        pin_schema: 1\n        snapshot: {}\n"
    )
    store = PinStore(path)
    before = path.read_bytes()
    assert store.canary_baseline("fixture") is None
    assert store.canary_baseline("unpinned") is None
    assert store.schema_warnings("fixture")[0].code == "pin_schema_outdated"
    assert path.read_bytes() == before


def _corrupt_v2_store(tmp_path: Path, field: str, value: object) -> PinStore:
    store = PinStore(tmp_path / "pins.yaml")
    tool = ToolInfo.model_validate_json(
        (Path(__file__).parent / "fixtures" / "pinning" / "tool-v2.json").read_text()
    )
    store.pin_server("fixture", [tool, tool.model_copy(update={"name": "baseline_only"})])
    raw = yaml.safe_load(store.path.read_text())
    entry = raw["servers"]["fixture"]["tools"][tool.name]
    target = entry if field == "snapshot" else entry["snapshot"]
    if value is None:
        del target[field]
    else:
        target[field] = value
    store.path.write_text(yaml.safe_dump(raw))
    return PinStore(store.path)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("input_schema", "invalid-snapshot-value", id="invalid-schema"),
        pytest.param("snapshot", {}, id="empty-snapshot"),
        pytest.param("snapshot", None, id="missing-snapshot"),
        pytest.param("annotations", None, id="missing-annotations"),
    ],
)
async def test_corrupt_v2_pins_warn_and_run_session_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    store = _corrupt_v2_store(tmp_path, field, value)
    monkeypatch.setattr("mcp_audit.pinning.PinStore", lambda: store)
    before = store.path.read_bytes()
    trace = tmp_path / "events.jsonl"
    config = make_server_config(name="fixture", command=sys.executable, args=[FIXTURE, "stable", str(trace)])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    audit = report.audits[0]
    assert audit.connection_status == "connected"
    assert report.servers_failed == 0 and report.servers_connected == 1
    assert audit.canary is not None and audit.canary.baseline_source == "session"
    assert audit.canary.status == "complete" and audit.canary.completed_calls == 5
    assert audit.canary.baseline_hash == audit.canary.current_hash
    assert not audit.drift_findings
    assert {warning.code for warning in report.warnings} == {"pin_baseline_corrupted", "pin_unsigned"}
    warning = next(warning for warning in report.warnings if warning.code == "pin_baseline_corrupted")
    assert warning.code == "pin_baseline_corrupted"
    assert warning.check == "canary_check" and warning.servers == [config.name]
    assert "using an in-session baseline only" in warning.message
    assert "invalid-snapshot-value" not in report.model_dump_json()
    assert store.path.read_bytes() == before


def test_identity_count_cli_validation_and_forwarding(tmp_path: Path) -> None:
    trace = tmp_path / "events.jsonl"
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"fixture": {"command": sys.executable, "args": [FIXTURE, "tools", str(trace)]}}}
        )
    )
    output = tmp_path / "report.json"
    args = [
        "scan",
        "--config",
        str(config),
        "--config-only",
        "--override-config",
        "/dev/null",
        "--canary-check",
        "--canary-identities",
        "1",
        "--json",
        str(output),
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    audit = json.loads(output.read_text())["audits"][0]
    assert len(audit["canary"]["client_identities"]) == 1 and not audit["drift_findings"]
    for value in ("0", "3"):
        result = CliRunner().invoke(main, ["scan", "--canary-identities", value])
        assert result.exit_code == 2 and "Invalid value for '--canary-identities'" in result.output


@pytest.mark.anyio
@pytest.mark.parametrize("identities", [0, 3, -1])
async def test_engine_rejects_unbounded_identity_count(identities: int) -> None:
    with pytest.raises(ValueError, match="Canary identities must be 1 or 2"):
        await run_scan(ScanOptions(canary_check=True, canary_identities=identities), servers=[])
