"""Fixture-backed v2 pin normalization and explicit legacy migration coverage."""

from __future__ import annotations

import hashlib
import io
import json
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import anyio
import pytest
import yaml
from mcp.types import Tool as SdkTool
from rich.console import Console

from mcp_audit import pin_cli, pinning
from mcp_audit.canonical import canonical_json_bytes
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.escalation import EscalationAnalyzer, detect_session_drift
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ServerAudit, ToolAnnotations, ToolInfo
from mcp_audit.pinning import PinStore, canonical_tool_surface, surface_hash
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

FIXTURES = Path(__file__).parent / "fixtures" / "pinning"


def _report(audit: ServerAudit) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="fixture",
        os_platform="fixture",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=len(audit.tools),
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0,
    )


def _tool() -> ToolInfo:
    return ToolInfo.model_validate_json((FIXTURES / "tool-v2.json").read_text())


def _legacy(tmp_path: Path) -> PinStore:
    path = tmp_path / "pins.yaml"
    path.write_bytes((FIXTURES / "legacy-v1.yaml").read_bytes())
    return PinStore(path)


def _mixed(tmp_path: Path, *tools: ToolInfo) -> PinStore:
    """An unsigned v2 entry that retains the fixture's v1 ``status`` row."""
    store = PinStore(tmp_path / "pins.yaml")
    store.pin_server("fixture", list(tools))
    raw = yaml.safe_load(store.path.read_text())
    legacy = yaml.safe_load((FIXTURES / "legacy-v1.yaml").read_text())
    raw["servers"]["fixture"]["tools"]["status"] = legacy["servers"]["fixture"]["tools"]["status"]
    store.path.write_text(yaml.safe_dump(raw))
    return PinStore(store.path)


def test_canonical_bytes_match_golden_and_both_hash_apis(tmp_path: Path) -> None:
    tool = _tool()
    golden = (FIXTURES / "tool-v2.canonical.json").read_bytes()
    assert canonical_json_bytes(canonical_tool_surface(tool)) == golden
    expected = "sha256:" + hashlib.sha256(golden).hexdigest()
    assert PinStore(tmp_path / "pins.yaml").compute_hash(tool) == surface_hash(tool) == expected
    assert surface_hash(canonical_tool_surface(tool)) == expected
    assert canonical_tool_surface(tool)["inputSchema"] == tool.input_schema
    # Preserve the served JSON number rather than coercing 1.0 to 1.
    assert surface_hash({"number": 1.0}) != surface_hash({"number": 1})


@pytest.mark.parametrize(
    "annotations",
    [
        None,
        {},
        {
            "read_only_hint": False,
            "destructive_hint": True,
            "idempotent_hint": False,
            "open_world_hint": True,
        },
        {"read_only_hint": None, "destructive_hint": None},
    ],
)
def test_annotation_defaults_hash_identically(annotations: dict[str, object] | None) -> None:
    default = ToolInfo(name="status", input_schema={})
    filled = ToolInfo.model_validate({**default.model_dump(), "annotations": annotations})
    assert surface_hash(default) == surface_hash(filled)


@pytest.mark.parametrize("field", ["description", "title", "output_schema", "icons", "meta", "annotations"])
def test_null_and_omitted_optionals_hash_identically(field: str) -> None:
    assert surface_hash(ToolInfo(name="status")) == surface_hash(
        ToolInfo.model_validate({"name": "status", field: None})
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_v2_rejects_nonfinite_json_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        surface_hash({"number": value})


@pytest.mark.parametrize(
    "field", ["title", "description", "input_schema", "output_schema", "icons", "meta", "annotations"]
)
def test_each_covered_field_changes_pin_hash(tmp_path: Path, field: str) -> None:
    tool = _tool()
    store = PinStore(tmp_path / "pins.yaml")
    store.pin_server("fixture", [tool])
    changed = tool.model_copy(update={field: None})
    (finding,) = store.check_drift("fixture", [changed])
    assert finding.status.value == "changed"
    assert f"{field.replace('_', ' ')} changed" in finding.details or f"{field} changed" in finding.details


def test_v2_roundtrip_restores_all_fields(tmp_path: Path) -> None:
    tool = _tool()
    store = PinStore(tmp_path / "pins.yaml")
    store.pin_server("fixture", [tool])
    reloaded = PinStore(store.path)
    assert reloaded.baseline_tools("fixture") == [tool]
    assert reloaded.schema_warnings("fixture") == []
    raw = yaml.safe_load(store.path.read_text())
    assert raw["pin_schema"] == 2
    entry = raw["servers"]["fixture"]["tools"]["status"]
    assert entry["pin_schema"] == 2
    assert entry["canonical_form"] == "mcpaudit.tool-surface.v2"


def test_connector_preserves_v2_fields_and_empty_input_schema() -> None:
    wire = canonical_tool_surface(_tool())
    wire["_meta"] = wire.pop("meta")
    converted = ServerConnector._convert_tool(SdkTool.model_validate(wire))
    assert canonical_tool_surface(converted) == canonical_tool_surface(_tool())
    assert ServerConnector._convert_tool(SdkTool(name="empty", input_schema={})).input_schema == {}


def test_session_default_fill_has_no_drift_but_annotation_flip_does() -> None:
    tool = ToolInfo(name="status", input_schema={})
    filled = tool.model_copy(update={"annotations": ToolAnnotations(destructive_hint=True)})
    before: dict[str, dict[str, object]] = {"tools": {tool.name: canonical_tool_surface(tool)}}
    after: dict[str, dict[str, object]] = {"tools": {tool.name: canonical_tool_surface(filled)}}
    assert detect_session_drift("fixture", before, after, 1) == []
    safe = tool.model_copy(update={"annotations": ToolAnnotations(read_only_hint=True)})
    (finding,) = detect_session_drift(
        "fixture", {"tools": {tool.name: canonical_tool_surface(safe)}}, after, 2
    )
    assert [field.path for field in finding.field_changes] == ["/annotations/readOnlyHint"]


@pytest.mark.parametrize(
    ("old", "new", "field"),
    [
        ({"read_only_hint": True}, {"read_only_hint": False}, "readOnlyHint"),
        ({"destructive_hint": False}, {"destructive_hint": True}, "destructiveHint"),
        ({}, {"destructive_hint": True}, "destructiveHint"),
        ({"open_world_hint": False}, {"open_world_hint": True}, "openWorldHint"),
        ({"read_only_hint": True}, {}, "readOnlyHint"),
        ({"open_world_hint": False}, {}, "openWorldHint"),
    ],
)
def test_security_annotation_deltas_are_explicit_high(
    old: dict[str, bool],
    new: dict[str, bool],
    field: str,
) -> None:
    baseline = ToolInfo.model_validate({"name": "status", "annotations": old})
    current = ToolInfo.model_validate({"name": "status", "annotations": new})
    findings = EscalationAnalyzer().analyze_server("fixture", [baseline], [current])
    (delta,) = [finding for finding in findings if finding.kind.value == "annotation_delta"]
    assert delta.severity.value == "high" and delta.annotation_changes == [field]
    audit = ServerAudit(
        server=make_server_config(name="fixture"), connection_status="connected", escalation_findings=[delta]
    )
    report = _report(audit)
    result = SarifGenerator().generate(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "MCP018" and result["level"] == "error"
    assert field in result["message"]["text"]
    assert delta.model_dump(mode="json")["annotation_changes"] == [field]
    assert result["properties"]["annotation_changes"] == [field]
    assert field in HtmlReportGenerator().generate(report)
    output = io.StringIO()
    ReportGenerator(console=Console(file=output, width=160)).render_terminal(report)
    assert field in output.getvalue()


def test_legacy_fixture_is_withheld_and_warns_without_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _legacy(tmp_path)
    original = store.path.read_bytes()
    current = _tool().model_copy(update={"input_schema": {"type": "object"}})
    # Never compared: neither a match nor a change is reported against v1 rows.
    assert store.check_drift("fixture", [current]) == []
    assert store.check_drift("fixture", [current.model_copy(update={"description": "Changed status."})]) == []
    assert store.baseline_tools("fixture") == [] and store.canary_baseline("fixture") is None
    assert store.tool_count("fixture") == 0
    monkeypatch.setattr(pinning, "PinStore", lambda: store)
    report = anyio.run(
        partial(
            run_scan,
            ScanOptions(config_only=True, skip_connect=True, pin_check=True),
            servers=[make_server_config(name="fixture")],
        )
    )
    (warning,) = [warning for warning in report.warnings if warning.code == "pin_schema_outdated"]
    assert warning.servers == ["fixture"]
    assert "is not compared: status" in warning.message
    assert "--refresh fixture --apply" in warning.message
    (withheld,) = [warning for warning in report.warnings if warning.code == "pin_baseline_withheld"]
    assert withheld.check == "pin_check" and withheld.servers == ["fixture"]
    assert store.path.read_bytes() == original


def test_mixed_entry_excludes_v1_rows_from_drift_and_lists_them_uncovered(tmp_path: Path) -> None:
    store = _mixed(tmp_path, ToolInfo(name="new", description="New"))
    assert store.legacy_tool_names("fixture") == {"status"} and not store.legacy_entry("fixture")
    assert store.baseline_usable("fixture")
    original = store.path.read_bytes()
    status = ToolInfo(name="status", description="Changed status.", input_schema={"type": "object"})
    new = ToolInfo(name="new", description="New")
    # The v1 row is neither CHANGED nor REMOVED nor NEW; the v2 row still compares.
    assert store.check_drift("fixture", [status, new]) == []
    assert store.check_drift("fixture", [new]) == []
    assert [f.status.value for f in store.check_drift("fixture", [])] == ["removed"]
    assert [(f.tool_name, f.status.value) for f in store.check_drift("fixture", [status])] == [
        ("new", "removed")
    ]
    findings = store.check_drift("fixture", [status, new.model_copy(update={"description": "Changed"})])
    assert [(f.tool_name, f.status.value) for f in findings] == [("new", "changed")]
    findings = store.check_drift("fixture", [status, new, ToolInfo(name="extra")])
    assert [(f.tool_name, f.status.value) for f in findings] == [("extra", "new")]
    (warning,) = store.schema_warnings("fixture")
    assert warning.code == "pin_schema_outdated"
    assert "not compared and count as uncovered: status" in warning.message
    baseline = store.canary_baseline("fixture")
    assert baseline is not None and set(baseline["tools"]) == {"new"}
    assert set(baseline[pinning.CANARY_UNCOVERED_TOOLS_KEY]) == {"status"}
    assert store.path.read_bytes() == original


def test_pinning_replaces_a_v1_entry_and_upgrades_mixed_rows_only_explicitly(tmp_path: Path) -> None:
    store = _legacy(tmp_path)
    entry = yaml.safe_load(store.path.read_text())["servers"]["fixture"]["tools"]["status"]
    store.pin_server("other", [_tool()])
    assert yaml.safe_load(store.path.read_text())["servers"]["fixture"]["tools"]["status"] == entry
    assert store.legacy_tool_names("fixture") == {"status"}
    # A genuine v1 entry is never carried forward: pinning replaces it wholesale.
    store.pin_server("fixture", [ToolInfo(name="new")])
    assert store.legacy_tool_names("fixture") == set()
    assert set(yaml.safe_load(store.path.read_text())["servers"]["fixture"]["tools"]) == {"new"}
    # A retained v1 row in a mixed entry upgrades only when its tool is pinned.
    mixed = _mixed(tmp_path, ToolInfo(name="new"))
    assert mixed.legacy_tool_names("fixture") == {"status"}
    mixed.pin_server("fixture", [ToolInfo(name="new")])
    assert mixed.legacy_tool_names("fixture") == {"status"}
    mixed.pin_server("fixture", [_tool()])
    assert mixed.legacy_tool_names("fixture") == set()


@pytest.mark.parametrize("server_name", ["fixture[/yellow]", "[bold]fixture[/bold]"])
def test_legacy_status_warning_renders_markup_names_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server_name: str
) -> None:
    store = _legacy(tmp_path)
    data = yaml.safe_load(store.path.read_text())
    data["servers"][server_name] = data["servers"].pop("fixture")
    store.path.write_text(yaml.safe_dump(data))
    store = PinStore(store.path)
    original = store.path.read_bytes()
    (warning,) = store.schema_warnings(server_name)
    output = io.StringIO()
    monkeypatch.setattr(pin_cli, "console", Console(file=output, width=600, highlight=False))

    pin_cli._render_pin_status(store, json_status=False)

    assert warning.message in output.getvalue()
    assert server_name in output.getvalue()
    assert store.path.read_bytes() == original


@pytest.mark.parametrize("as_json", [False, True])
def test_legacy_refresh_labels_uncovered_fields_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    as_json: bool,
) -> None:
    store = _legacy(tmp_path)
    original = store.path.read_bytes()
    current = _tool().model_copy(update={"input_schema": {"type": "object"}})
    audit = ServerAudit(
        server=make_server_config(name="fixture"), connection_status="connected", tools=[current]
    )

    async def fake_scan(*args: object, **kwargs: object) -> AuditReport:
        return _report(audit)

    monkeypatch.setattr(pin_cli, "run_scan", fake_scan)
    anyio.run(pin_cli._run_pin_refresh, "fixture", store, False, as_json)
    output = capsys.readouterr().out
    if as_json:
        payload = json.loads(output)
        assert {row["field"] for row in payload["uncovered_fields"]} == {
            "annotations",
            "title",
            "outputSchema",
            "icons",
            "meta",
        }
        assert all(row["summary"] == "not previously covered" for row in payload["uncovered_fields"])
        # 3.0 never hashes v1: the full current surface is reviewed as a new pin.
        assert [(row["tool_name"], row["status"]) for row in payload["drift"]] == [("status", "new")]
        assert payload["escalation"] == [] and payload["provenance"] == []
        assert payload["baseline_verified"] is False
        assert "not compared" in payload["baseline_note"]
        assert "mcp-audit pin --refresh SERVER" in payload["baseline_note"]
    else:
        assert "not previously covered" in output and "outputSchema" in output
        assert "1 new, 0 changed, 0 removed" in output
        assert "No drift found" not in output
        assert "mcp-audit pin --refresh SERVER" in output
    assert store.path.read_bytes() == original


def test_legacy_escalation_ignores_uncovered_hints_but_retains_text_deltas(tmp_path: Path) -> None:
    # A genuine v1 entry has no baseline; a mixed entry restores its v1 row uncovered.
    assert _legacy(tmp_path).baseline_tools("fixture") == []
    store = _mixed(tmp_path, ToolInfo(name="other"))
    baseline = [tool for tool in store.baseline_tools("fixture") if tool.name == "status"]
    assert len(baseline) == 1 and baseline[0].annotations is None
    current = baseline[0].model_copy(
        update={"annotations": ToolAnnotations(read_only_hint=False, destructive_hint=True)}
    )
    analyzer = EscalationAnalyzer()
    assert (
        analyzer.analyze_server(
            "fixture", baseline, [current], uncovered_annotations=store.legacy_tool_names("fixture")
        )
        == []
    )
    changed = current.model_copy(update={"description": "Execute a shell command on the host"})
    findings = analyzer.analyze_server(
        "fixture", baseline, [changed], uncovered_annotations=store.legacy_tool_names("fixture")
    )
    assert any(finding.kind.value == "capability" for finding in findings)


def test_icon_null_optionals_and_annotation_title_are_omitted() -> None:
    omitted = ToolInfo(name="status", icons=[{"src": "https://example.test/icon.png"}])
    filled = omitted.model_copy(
        update={
            "icons": [
                {"src": "https://example.test/icon.png", "mimeType": None, "sizes": None, "theme": None}
            ],
            "annotations": ToolAnnotations(title=None),
        }
    )
    assert surface_hash(omitted) == surface_hash(filled)


def test_duplicate_tools_refused_before_pin_write(tmp_path: Path) -> None:
    store = _legacy(tmp_path)
    original = store.path.read_bytes()
    with pytest.raises(ValueError, match="duplicate tool names"):
        store.pin_server("fixture", [_tool(), _tool()])
    assert store.path.read_bytes() == original


@pytest.mark.parametrize("field", ["title", "output_schema", "icons", "meta", "annotations"])
def test_new_snapshot_fields_retain_credential_redaction(tmp_path: Path, field: str) -> None:
    raw: object = "token=synthetic-secret"
    if field == "output_schema":
        raw = {"type": "object", "description": raw}
    elif field == "icons":
        raw = [{"src": "https://example.test/icon.png?token=synthetic-secret"}]
    elif field == "meta":
        raw = {"token": "synthetic-secret"}
    elif field == "annotations":
        raw = {"title": raw}
    tool = ToolInfo.model_validate({"name": "status", field: raw})
    store = PinStore(tmp_path / "pins.yaml")
    store.pin_server("fixture", [tool])
    assert "synthetic-secret" not in store.path.read_text()
    assert store.check_drift("fixture", [tool]) == []
