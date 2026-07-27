from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

import mcp_audit.agent_ui_cli as agent_ui_cli
from mcp_audit.agent_ui_models import (
    A2UIFixtureManifest,
    A2UIMessage,
    AgentUIReport,
    MCPAppsFixture,
)
from mcp_audit.agent_ui_scanner import (
    AgentUIInputError,
    render_agent_ui_html,
    report_json_bytes,
    scan_agent_ui_path,
)
from mcp_audit.cli import main

FIXTURE_ROOT = Path("tests/fixtures/agent_ui")
VULNERABLE_FIXTURES = {
    "mcpui001-authority-vulnerable.json": "MCPUI001",
    "mcpui002-stale-vulnerable.jsonl": "MCPUI002",
    "mcpui003-invocation-vulnerable.json": "MCPUI003",
    "mcpui004-untrusted-vulnerable.jsonl": "MCPUI004",
    "mcpui005-unknown-vulnerable.jsonl": "MCPUI005",
    "mcpui006-external-vulnerable.json": "MCPUI006",
}


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / name


def test_fixture_inventory_has_six_positive_vulnerable_negative_triplets() -> None:
    fixtures = sorted(FIXTURE_ROOT.iterdir())
    assert len(fixtures) == 18
    for rule in range(1, 7):
        prefix = f"mcpui{rule:03d}-"
        members = [path.name for path in fixtures if path.name.startswith(prefix)]
        assert len(members) == 3
        assert any("-positive." in name for name in members)
        assert any("-vulnerable." in name for name in members)
        assert any("-negative." in name for name in members)


@pytest.mark.parametrize(("name", "rule_id"), VULNERABLE_FIXTURES.items())
def test_each_vulnerable_control_fires_only_its_stable_rule(name: str, rule_id: str) -> None:
    report = scan_agent_ui_path(_fixture(name))
    assert report.verdict == "fail"
    assert [finding.rule_id for finding in report.findings] == [rule_id]
    finding = report.findings[0]
    assert finding.severity.value == "high"
    assert finding.evidence
    assert finding.remediation
    assert finding.assumptions
    assert finding.protocol in {"mcp-apps", "a2ui"}


@pytest.mark.parametrize(
    "path",
    sorted(path for path in FIXTURE_ROOT.iterdir() if "-positive." in path.name or "-negative." in path.name),
    ids=lambda path: path.name,
)
def test_positive_and_negative_controls_remain_clean(path: Path) -> None:
    report = scan_agent_ui_path(path)
    assert report.verdict == "pass"
    assert report.findings == []


def test_report_is_deterministic_and_strictly_round_trips() -> None:
    path = _fixture("mcpui004-untrusted-vulnerable.jsonl")
    first = scan_agent_ui_path(path)
    second = scan_agent_ui_path(path)
    assert first == second
    first_bytes = report_json_bytes(first)
    assert first_bytes == report_json_bytes(second)
    assert first_bytes.endswith(b"\n")
    assert AgentUIReport.model_validate_json(first_bytes, strict=True) == first


def test_report_keeps_protocols_and_claim_ceiling_distinct() -> None:
    mcp_report = scan_agent_ui_path(_fixture("mcpui001-authority-positive.json"))
    a2ui_report = scan_agent_ui_path(_fixture("mcpui002-stale-positive.jsonl"))
    assert mcp_report.input_kind == "mcp-apps-metadata"
    assert mcp_report.protocol == "mcp-apps"
    assert a2ui_report.input_kind == "a2ui-jsonl"
    assert a2ui_report.protocol == "a2ui"
    combined_ceiling = " ".join(a2ui_report.claim_ceiling)
    assert "no interoperability" in combined_ceiling
    unsupported = " ".join(a2ui_report.unsupported_inputs)
    assert "AG-UI" in unsupported
    assert "WebMCP" in unsupported
    assert "A2UI v0.8" in unsupported


def test_offline_html_is_inert_deterministic_and_escapes_findings() -> None:
    report = scan_agent_ui_path(_fixture("mcpui001-authority-vulnerable.json"))
    unsafe = report.findings[0].model_copy(update={"target": "<img src=x onerror=alert(1)>"})
    escaped_report = report.model_copy(update={"findings": [unsafe]})
    first = render_agent_ui_html(escaped_report)
    assert first == render_agent_ui_html(escaped_report)
    assert "default-src 'none'" in first
    assert "<script" not in first
    assert "<img src=x" not in first
    assert "&lt;img src=x onerror=alert(1)&gt;" in first
    assert "The canonical evidence is the JSON report" in first


def test_scanner_has_no_network_or_process_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"runtime effect attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert scan_agent_ui_path(_fixture("mcpui006-external-vulnerable.json")).verdict == "fail"
    assert scan_agent_ui_path(_fixture("mcpui005-unknown-positive.jsonl")).verdict == "pass"


def test_openai_alias_conflict_is_unknown_not_safe(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["tools"][0]["_meta"]["openai/outputTemplate"] = "ui://different/template"
    path = tmp_path / "alias-conflict.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert [finding.rule_id for finding in report.findings] == ["MCPUI000"]
    assert "conflicts" in report.findings[0].evidence[0]


def test_openai_compatibility_metadata_conflicts_are_unknown(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["tools"][0]["_meta"]["openai/visibility"] = "private"
    resource_meta = payload["resources"][0]["_meta"]
    resource_meta["ui"]["domain"] = "https://standard-widget.example"
    resource_meta["openai/widgetDomain"] = "https://openai-widget.example"
    resource_meta["openai/widgetCSP"]["connect_domains"] = ["https://analytics.example"]
    path = tmp_path / "compatibility-conflicts.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "unknown"
    evidence = {item for finding in report.findings for item in finding.evidence}
    assert any("visibility conflicts" in item for item in evidence)
    assert any("widgetDomain" in item for item in evidence)
    assert any("connectDomains" in item for item in evidence)


def test_openai_only_csp_metadata_does_not_conflict_with_absent_standard_csp(
    tmp_path: Path,
) -> None:
    payload = json.loads(_fixture("mcpui006-external-positive.json").read_text())
    payload["resources"][0]["_meta"].pop("ui")
    path = tmp_path / "openai-only-csp.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "pass"
    assert report.findings == []


def test_unsupported_a2ui_version_is_unknown_not_safe(tmp_path: Path) -> None:
    lines = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()
    message = json.loads(lines[1])
    message["version"] = "v1.0"
    lines[1] = json.dumps(message)
    path = tmp_path / "unsupported.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert any(finding.rule_id == "MCPUI000" for finding in report.findings)


def test_unsupported_a2ui_component_is_unknown_not_safe(tmp_path: Path) -> None:
    lines = _fixture("mcpui005-unknown-positive.jsonl").read_text().splitlines()
    message = json.loads(lines[2])
    message["updateComponents"]["components"][1]["component"] = "RemoteCode"
    lines[2] = json.dumps(message)
    path = tmp_path / "unsupported-component.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert [finding.rule_id for finding in report.findings] == ["MCPUI000", "MCPUI000"]


def test_unreachable_vulnerable_a2ui_component_is_a_negative_control(tmp_path: Path) -> None:
    lines = _fixture("mcpui005-unknown-positive.jsonl").read_text().splitlines()
    message = json.loads(lines[2])
    message["updateComponents"]["components"].append(
        {
            "id": "unreachable-green",
            "component": "StatusBadge",
            "label": "Pass",
            "state": "pass",
            "tone": "green",
        }
    )
    lines[2] = json.dumps(message)
    path = tmp_path / "unreachable.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "pass"
    assert report.findings == []


def test_duplicate_json_keys_are_rejected_before_model_validation(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"program_owned":true,"program_owned":true}', encoding="utf-8")
    with pytest.raises(AgentUIInputError, match="invalid JSON fixture"):
        scan_agent_ui_path(path)


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    link = tmp_path / "fixture.json"
    link.symlink_to(_fixture("mcpui001-authority-positive.json").resolve())
    with pytest.raises(AgentUIInputError, match="symlink"):
        scan_agent_ui_path(link)


@pytest.mark.parametrize(
    ("contract", "model"),
    [
        ("mcp-apps-fixture", MCPAppsFixture),
        ("a2ui-fixture-manifest", A2UIFixtureManifest),
        ("a2ui-message", A2UIMessage),
        ("report", AgentUIReport),
    ],
)
def test_schema_command_matches_live_strict_model(contract: str, model: type[object]) -> None:
    result = CliRunner().invoke(main, ["agent-ui", "schema", contract])
    assert result.exit_code == 0, result.output
    schema = json.loads(result.output)
    assert schema == model.model_json_schema()  # type: ignore[attr-defined]
    assert schema["additionalProperties"] is False


def test_strict_input_schema_rejects_unknown_fields() -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["unsupported"] = True
    with pytest.raises(ValidationError):
        MCPAppsFixture.model_validate(payload, strict=True)


def test_cli_writes_json_and_offline_html_and_refuses_implicit_overwrite(
    tmp_path: Path,
) -> None:
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    runner = CliRunner()
    args = [
        "agent-ui",
        "scan",
        str(_fixture("mcpui001-authority-positive.json")),
        "--json",
        str(json_path),
        "--html",
        str(html_path),
    ]
    first = runner.invoke(main, args)
    assert first.exit_code == 0, first.output
    report = AgentUIReport.model_validate_json(json_path.read_bytes(), strict=True)
    assert report.verdict == "pass"
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    second = runner.invoke(main, args)
    assert second.exit_code != 0
    assert "use --force" in second.output
    forced = runner.invoke(main, [*args, "--force"])
    assert forced.exit_code == 0, forced.output


def test_cli_returns_nonzero_after_writing_vulnerable_reports(tmp_path: Path) -> None:
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    result = CliRunner().invoke(
        main,
        [
            "agent-ui",
            "scan",
            str(_fixture("mcpui006-external-vulnerable.json")),
            "--json",
            str(json_path),
            "--html",
            str(html_path),
        ],
    )
    assert result.exit_code == 1
    assert AgentUIReport.model_validate_json(json_path.read_bytes(), strict=True).verdict == "fail"
    assert html_path.exists()


def test_cli_uses_exit_two_for_invalid_input(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    result = CliRunner().invoke(main, ["agent-ui", "scan", str(invalid)])
    assert result.exit_code == 2
    assert "invalid JSON fixture" in result.output


def test_manifest_only_a2ui_fixture_is_unknown(tmp_path: Path) -> None:
    manifest = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()[0]
    path = tmp_path / "manifest-only.jsonl"
    path.write_text(manifest + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert "no A2UI messages" in report.findings[0].evidence[0]


@pytest.mark.parametrize("terminal_change", ["delete", "safe-replacement"])
def test_a2ui_prior_vulnerable_state_cannot_be_erased(
    tmp_path: Path,
    terminal_change: str,
) -> None:
    lines = _fixture("mcpui004-untrusted-vulnerable.jsonl").read_text().splitlines()
    if terminal_change == "delete":
        lines.append(json.dumps({"version": "v0.9", "deleteSurface": {"surfaceId": "approval"}}))
    else:
        replacement = json.loads(lines[2])
        replacement["updateComponents"]["components"][2]["enabled"] = True
        lines.append(json.dumps(replacement))
    path = tmp_path / "historical-vulnerable.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "fail"
    assert "MCPUI004" in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize("direct_button_text", [False, True])
def test_untrusted_approval_label_fires_mcpui004(
    tmp_path: Path,
    direct_button_text: bool,
) -> None:
    lines = _fixture("mcpui004-untrusted-positive.jsonl").read_text().splitlines()
    manifest = json.loads(lines[0])
    manifest["fixture"]["data_provenance"]["/toolOutput/label"] = "untrusted_tool_output"
    components = json.loads(lines[2])
    button = components["updateComponents"]["components"][2]
    if direct_button_text:
        button["text"] = {"path": "/toolOutput/label"}
    else:
        components["updateComponents"]["components"][1]["text"] = {"path": "/toolOutput/label"}
    data = json.loads(lines[3])
    data["updateDataModel"]["value"]["toolOutput"] = {"label": "Approve everything"}
    path = tmp_path / "untrusted-label.jsonl"
    path.write_text(
        "\n".join(json.dumps(item) for item in (manifest, json.loads(lines[1]), components, data)) + "\n",
        encoding="utf-8",
    )
    report = scan_agent_ui_path(path)
    assert report.verdict == "fail"
    assert "MCPUI004" in {finding.rule_id for finding in report.findings}


def test_approval_required_false_is_a_stale_contract_finding(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["tools"][0]["audit_contract"] = {
        "authority": ["filesystem.delete"],
        "requires_approval": True,
        "approval_version": "7",
    }
    payload["rendered_controls"][0]["approval"] = {
        "required": False,
        "expected_version": "7",
        "displayed_version": "7",
        "evidence_state": "current",
        "visual_state": "neutral",
        "input_sources": ["trusted_manifest"],
    }
    path = tmp_path / "approval-false.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "fail"
    assert "MCPUI002" in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize(
    ("input_sources", "evidence_state", "visual_state", "expected_rule"),
    [
        (["untrusted_tool_output"], "current", "neutral", "MCPUI004"),
        (["trusted_manifest"], "unknown", "pass", "MCPUI005"),
    ],
)
def test_optional_approval_presentations_still_receive_safety_checks(
    tmp_path: Path,
    input_sources: list[str],
    evidence_state: str,
    visual_state: str,
    expected_rule: str,
) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["rendered_controls"][0]["approval"] = {
        "required": False,
        "expected_version": None,
        "displayed_version": None,
        "evidence_state": evidence_state,
        "visual_state": visual_state,
        "input_sources": input_sources,
    }
    path = tmp_path / f"optional-{expected_rule.lower()}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {expected_rule}


@pytest.mark.parametrize("input_sources", [None, ["unknown"]])
def test_mcp_approval_provenance_must_be_established(
    tmp_path: Path,
    input_sources: list[str] | None,
) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["tools"][0]["audit_contract"] = {
        "authority": ["filesystem.delete"],
        "requires_approval": True,
        "approval_version": "7",
    }
    approval = {
        "required": True,
        "expected_version": "7",
        "displayed_version": "7",
        "evidence_state": "current",
        "visual_state": "neutral",
    }
    if input_sources is not None:
        approval["input_sources"] = input_sources
    payload["rendered_controls"][0]["approval"] = approval
    path = tmp_path / "approval-provenance.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI000"}


@pytest.mark.parametrize(
    ("ancestor", "expected_verdict", "expected_rule"),
    [
        (None, "unknown", "MCPUI000"),
        ("untrusted_tool_output", "fail", "MCPUI004"),
        ("trusted_manifest", "pass", None),
    ],
)
def test_a2ui_approval_provenance_uses_nearest_declared_ancestor(
    tmp_path: Path,
    ancestor: str | None,
    expected_verdict: str,
    expected_rule: str | None,
) -> None:
    lines = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()
    manifest = json.loads(lines[0])
    manifest["fixture"]["data_provenance"] = {} if ancestor is None else {"/approval": ancestor}
    lines[0] = json.dumps(manifest)
    path = tmp_path / "ancestor-provenance.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == expected_verdict
    if expected_rule is None:
        assert report.findings == []
    else:
        assert expected_rule in {finding.rule_id for finding in report.findings}


def test_untrusted_status_badge_cannot_render_pass(tmp_path: Path) -> None:
    lines = _fixture("mcpui005-unknown-negative.jsonl").read_text().splitlines()
    manifest = json.loads(lines[0])
    manifest["fixture"]["data_provenance"] = {
        "/evidence/state": "untrusted_tool_output",
        "/evidence/label": "untrusted_tool_output",
        "/evidence/visualState": "untrusted_tool_output",
    }
    lines[0] = json.dumps(manifest)
    path = tmp_path / "untrusted-status-badge.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI005"}


def test_stale_status_badge_is_a_stale_contract_finding_even_when_green(
    tmp_path: Path,
) -> None:
    lines = _fixture("mcpui005-unknown-positive.jsonl").read_text().splitlines()
    components = json.loads(lines[2])
    components["updateComponents"]["components"][1]["tone"] = "green"
    lines[2] = json.dumps(components)
    data = json.loads(lines[3])
    evidence = data["updateDataModel"]["value"]["evidence"]
    evidence.update({"state": "stale", "label": "Passed", "visualState": "pass"})
    lines[3] = json.dumps(data)
    path = tmp_path / "stale-green-status.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI002"}


@pytest.mark.parametrize("component_kind", ["button", "badge"])
def test_out_of_domain_a2ui_evidence_state_is_unknown(
    tmp_path: Path,
    component_kind: str,
) -> None:
    if component_kind == "button":
        lines = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()
        data = json.loads(lines[3])
        data["updateDataModel"]["value"]["approval"]["evidenceState"] = "mystery"
        lines[3] = json.dumps(data)
    else:
        lines = _fixture("mcpui005-unknown-positive.jsonl").read_text().splitlines()
        data = json.loads(lines[3])
        data["updateDataModel"]["value"]["evidence"]["state"] = "mystery"
        lines[3] = json.dumps(data)
    path = tmp_path / f"unknown-state-{component_kind}.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI000"}


def test_unsupported_visual_state_does_not_mask_stale_approval(tmp_path: Path) -> None:
    lines = _fixture("mcpui002-stale-vulnerable.jsonl").read_text().splitlines()
    data = json.loads(lines[3])
    data["updateDataModel"]["value"]["approval"]["visualState"] = "mystery"
    lines[3] = json.dumps(data)
    path = tmp_path / "stale-with-unsupported-visual.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI000", "MCPUI002"}


def test_unsupported_badge_state_does_not_mask_unknown_green(tmp_path: Path) -> None:
    lines = _fixture("mcpui005-unknown-vulnerable.jsonl").read_text().splitlines()
    data = json.loads(lines[3])
    data["updateDataModel"]["value"]["evidence"]["visualState"] = "mystery"
    lines[3] = json.dumps(data)
    path = tmp_path / "unknown-green-with-unsupported-visual.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI000", "MCPUI005"}


def test_generic_host_cannot_consume_openai_only_binding(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui003-invocation-positive.json").read_text())
    payload["tools"][0]["_meta"]["ui"]["resourceUri"] = None
    payload["tools"][0]["_meta"]["openai/outputTemplate"] = "ui://settings/notifications"
    path = tmp_path / "generic-openai-only.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert any("OpenAI-specific" in evidence for finding in report.findings for evidence in finding.evidence)


def test_invalid_json_pointer_escape_is_unknown(tmp_path: Path) -> None:
    lines = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()
    components = json.loads(lines[2])
    components["updateComponents"]["components"][2]["approvalVersion"] = {"path": "/history~2version"}
    lines[2] = json.dumps(components)
    path = tmp_path / "invalid-pointer.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert all(finding.rule_id == "MCPUI000" for finding in report.findings)


def test_tool_call_excluded_from_app_visibility_is_unknown(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    payload["tools"][0]["_meta"]["ui"]["visibility"] = ["model"]
    payload["tools"][0]["_meta"]["openai/widgetAccessible"] = False
    path = tmp_path / "widget-access-denied.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert any("app access" in evidence for finding in report.findings for evidence in finding.evidence)


def test_malformed_component_field_shape_is_unknown(tmp_path: Path) -> None:
    lines = _fixture("mcpui005-unknown-positive.jsonl").read_text().splitlines()
    components = json.loads(lines[2])
    components["updateComponents"]["components"][0]["children"].append(17)
    lines[2] = json.dumps(components)
    path = tmp_path / "malformed-component.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert all(finding.rule_id == "MCPUI000" for finding in report.findings)


def test_duplicate_component_ids_are_unknown(tmp_path: Path) -> None:
    lines = _fixture("mcpui004-untrusted-positive.jsonl").read_text().splitlines()
    components = json.loads(lines[2])
    duplicate = dict(components["updateComponents"]["components"][2])
    components["updateComponents"]["components"].append(duplicate)
    lines[2] = json.dumps(components)
    path = tmp_path / "duplicate-components.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan_agent_ui_path(path)
    assert report.verdict == "unknown"
    assert all(finding.rule_id == "MCPUI000" for finding in report.findings)


def test_deep_json_nesting_is_rejected_with_controlled_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text('{"value":' + "[" * 65 + "0" + "]" * 65 + "}", encoding="utf-8")
    with pytest.raises(AgentUIInputError, match="nesting"):
        scan_agent_ui_path(path)
    result = CliRunner().invoke(main, ["agent-ui", "scan", str(path)])
    assert result.exit_code == 2
    assert "nesting" in result.output


def test_descriptor_bound_read_enforces_limit_after_fstat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "grown.json"
    path.write_bytes(b" " * (1_048_576 + 1))
    real_fstat = os.fstat

    def stale_small_fstat(descriptor: int) -> os.stat_result:
        observed = list(real_fstat(descriptor))
        observed[6] = 1
        return os.stat_result(observed)

    monkeypatch.setattr(os, "fstat", stale_small_fstat)
    with pytest.raises(AgentUIInputError, match="exceeds 1048576"):
        scan_agent_ui_path(path)


def test_scanner_does_not_reopen_fixture_by_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_read_bytes(path: Path) -> bytes:
        raise AssertionError(f"path reopened: {path}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    assert scan_agent_ui_path(_fixture("mcpui001-authority-positive.json")).verdict == "pass"


def test_approval_required_without_authoritative_version_is_unknown(
    tmp_path: Path,
) -> None:
    mcp_payload = json.loads(_fixture("mcpui001-authority-positive.json").read_text())
    mcp_payload["tools"][0]["audit_contract"]["requires_approval"] = True
    mcp_payload["rendered_controls"][0]["approval"] = {
        "required": True,
        "expected_version": "self-attested",
        "displayed_version": "self-attested",
        "evidence_state": "current",
        "visual_state": "neutral",
        "input_sources": ["trusted_manifest"],
    }
    mcp_path = tmp_path / "versionless.json"
    mcp_path.write_text(json.dumps(mcp_payload), encoding="utf-8")
    assert scan_agent_ui_path(mcp_path).verdict == "unknown"

    lines = _fixture("mcpui002-stale-positive.jsonl").read_text().splitlines()
    manifest = json.loads(lines[0])
    manifest["fixture"]["action_contracts"][0]["expected_approval_version"] = None
    lines[0] = json.dumps(manifest)
    a2ui_path = tmp_path / "versionless.jsonl"
    a2ui_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert scan_agent_ui_path(a2ui_path).verdict == "unknown"


def test_empty_mcp_ui_contract_is_unknown(tmp_path: Path) -> None:
    payload = json.loads(_fixture("mcpui006-external-negative.json").read_text())
    payload["resources"] = []
    payload["rendered_controls"] = []
    path = tmp_path / "empty-ui.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert scan_agent_ui_path(path).verdict == "unknown"


def test_a2ui_schema_exposes_strict_fixed_catalog_component_shapes() -> None:
    schema = A2UIMessage.model_json_schema()
    serialized = json.dumps(schema, sort_keys=True)
    assert '"discriminator"' in serialized
    assert "A2UIColumnComponent" in serialized
    assert schema["$defs"]["A2UIColumnComponent"]["additionalProperties"] is False


def test_cli_preflights_output_identity_and_complete_set(tmp_path: Path) -> None:
    runner = CliRunner()
    fixture = tmp_path / "fixture.json"
    original = _fixture("mcpui001-authority-positive.json").read_bytes()
    fixture.write_bytes(original)

    same_output = tmp_path / "same.out"
    same_result = runner.invoke(
        main,
        [
            "agent-ui",
            "scan",
            str(fixture),
            "--json",
            str(same_output),
            "--html",
            str(same_output),
            "--force",
        ],
    )
    assert same_result.exit_code == 2
    assert not same_output.exists()

    alias_result = runner.invoke(
        main,
        ["agent-ui", "scan", str(fixture), "--json", str(fixture), "--force"],
    )
    assert alias_result.exit_code == 2
    assert fixture.read_bytes() == original

    json_path = tmp_path / "partial.json"
    occupied_html = tmp_path / "occupied.html"
    occupied_html.write_text("occupied", encoding="utf-8")
    partial_result = runner.invoke(
        main,
        [
            "agent-ui",
            "scan",
            str(fixture),
            "--json",
            str(json_path),
            "--html",
            str(occupied_html),
        ],
    )
    assert partial_result.exit_code == 2
    assert not json_path.exists()
    assert occupied_html.read_text(encoding="utf-8") == "occupied"


def test_cli_rechecks_input_alias_against_opened_output_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_parent = tmp_path / "fixture"
    output_parent = tmp_path / "output"
    fixture_parent.mkdir()
    output_parent.mkdir()
    fixture = fixture_parent / "contract.json"
    fixture.write_bytes(_fixture("mcpui001-authority-positive.json").read_bytes())
    original = fixture.read_bytes()
    output = output_parent / fixture.name

    def retarget_output_parent(path: Path) -> int:
        assert path == output
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        return os.open(fixture_parent, flags)

    monkeypatch.setattr(agent_ui_cli, "_open_artifact_parent", retarget_output_parent)
    result = CliRunner().invoke(
        main,
        [
            "agent-ui",
            "scan",
            str(fixture),
            "--json",
            str(output),
            "--force",
        ],
    )

    assert result.exit_code == 2
    assert "must not alias the input fixture" in result.output
    assert fixture.read_bytes() == original
    assert not output.exists()


def test_cli_no_force_commit_does_not_clobber_post_preflight_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    json_path = tmp_path / "race.json"
    html_path = tmp_path / "race.html"
    real_stage = agent_ui_cli._stage_artifact

    def stage_with_competing_html(
        parent_fd: int,
        path: Path,
        content: bytes,
    ) -> agent_ui_cli._StagedArtifact:
        artifact = real_stage(parent_fd, path, content)
        if path == html_path:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(b"competitor")
        return artifact

    monkeypatch.setattr(agent_ui_cli, "_stage_artifact", stage_with_competing_html)
    result = CliRunner().invoke(
        main,
        [
            "agent-ui",
            "scan",
            str(_fixture("mcpui001-authority-positive.json")),
            "--json",
            str(json_path),
            "--html",
            str(html_path),
        ],
    )

    assert result.exit_code == 2
    assert "use --force" in result.output
    assert not json_path.exists()
    assert html_path.read_bytes() == b"competitor"


@pytest.mark.parametrize(
    "malformed_origin",
    ["https://:443", "https://docs.example:notaport", "https://docs.example:0"],
)
def test_malformed_https_authority_is_unknown_even_when_repeated(
    tmp_path: Path,
    malformed_origin: str,
) -> None:
    payload = json.loads(_fixture("mcpui006-external-positive.json").read_text())
    payload["rendered_controls"][0]["action"]["destination"] = malformed_origin
    payload["declared_external_destinations"] = [malformed_origin]
    payload["resources"][0]["_meta"]["openai/widgetCSP"]["redirect_domains"] = [malformed_origin]
    path = tmp_path / "malformed-origin.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = scan_agent_ui_path(path)

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPUI000"}
