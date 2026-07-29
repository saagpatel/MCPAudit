from __future__ import annotations

import json
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mcp_audit.a2ui_duplex_models import (
    A2UIDuplexFixture,
    A2UIDuplexReport,
    DuplexDisclosurePolicy,
)
from mcp_audit.a2ui_duplex_scanner import (
    a2ui_duplex_report_json_bytes,
    render_a2ui_duplex_sarif,
    scan_a2ui_duplex_path,
)
from mcp_audit.agent_ui_scanner import AgentUIInputError
from mcp_audit.cli import main

FIXTURE_ROOT = Path("tests/fixtures/a2ui_duplex")

TRIPLET_VULNERABLE_FIXTURES = {
    "mcpdup001-origin-vulnerable.json": "MCPDUP001",
    "mcpdup002-action-vulnerable.json": "MCPDUP002",
    "mcpdup003-causality-vulnerable.json": "MCPDUP003",
    "mcpdup004-capability-vulnerable.json": "MCPDUP004",
    "mcpdup005-error-vulnerable.json": "MCPDUP005",
    "mcpdup006-disclosure-vulnerable.json": "MCPDUP006",
}

EXTRA_VULNERABLE_FIXTURES = {
    "mcpdup001-removed-component-vulnerable.json": "MCPDUP001",
    "mcpdup002-undeclared-action-vulnerable.json": "MCPDUP002",
    "mcpdup003-causal-impossible-vulnerable.json": "MCPDUP003",
}


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / name


def _payload(name: str = "mcpdup001-origin-negative.json") -> dict[str, object]:
    return json.loads(_fixture(name).read_text(encoding="utf-8"))


def _write_payload(tmp_path: Path, payload: object, name: str = "fixture.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_fixture_inventory_has_six_negative_vulnerable_near_miss_triplets() -> None:
    fixtures = sorted(FIXTURE_ROOT.glob("*.json"))
    assert len(fixtures) >= 18
    for rule in range(1, 7):
        prefix = f"mcpdup{rule:03d}-"
        triplet = [
            path.name
            for path in fixtures
            if path.name.startswith(prefix)
            and any(control in path.name for control in ("-negative", "-vulnerable", "-near-miss"))
        ]
        assert any("-negative" in name for name in triplet)
        assert any("-vulnerable" in name for name in triplet)
        assert any("-near-miss" in name for name in triplet)


@pytest.mark.parametrize(
    ("name", "rule_id"),
    [*TRIPLET_VULNERABLE_FIXTURES.items(), *EXTRA_VULNERABLE_FIXTURES.items()],
)
def test_vulnerable_controls_fire_only_the_expected_rule(name: str, rule_id: str) -> None:
    report = scan_a2ui_duplex_path(_fixture(name))
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {rule_id}
    assert all(finding.status == "finding" for finding in report.findings)
    assert all(finding.observable_basis for finding in report.findings)


@pytest.mark.parametrize(
    "path",
    sorted(
        path
        for path in FIXTURE_ROOT.glob("*.json")
        if ("-negative" in path.name or "-near-miss" in path.name) and "absent-policy" not in path.name
    ),
    ids=lambda path: path.name,
)
def test_negative_and_near_miss_controls_remain_clean(path: Path) -> None:
    report = scan_a2ui_duplex_path(path)
    assert report.verdict == "pass"
    assert report.findings == []


def test_absent_disclosure_policy_is_unknown_not_safe_or_invented() -> None:
    report = scan_a2ui_duplex_path(_fixture("mcpdup006-absent-policy-unknown.json"))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unknown")]
    assert "no explicit disclosure policy" in report.findings[0].evidence[0]


def test_server_only_fixture_is_unknown_instead_of_silently_passing(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    payload["transcript"] = transcript[:2]
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unknown")]
    assert "no client-to-server return" in report.findings[0].evidence[0]


def test_malformed_action_declaration_is_unknown_not_undeclared_finding(
    tmp_path: Path,
) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    component = transcript[1]["message"]["updateComponents"]["components"][0]
    component["action"]["event"]["name"] = 7
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert all(item.rule_id == "MCPDUP000" for item in report.findings)
    assert not any(item.status == "finding" for item in report.findings)


def test_two_producer_profiles_and_both_supported_protocol_families_are_covered() -> None:
    reports = [
        scan_a2ui_duplex_path(_fixture("mcpdup001-origin-negative.json")),
        scan_a2ui_duplex_path(_fixture("mcpdup003-causality-near-miss.json")),
        scan_a2ui_duplex_path(_fixture("mcpdup005-error-near-miss.json")),
    ]
    assert {item.producer_profile for item in reports} == {"web-core-react", "flutter-a2ui"}
    assert {item.protocol_version for item in reports} == {"v0.9", "v1.0"}
    assert all(item.verdict == "pass" for item in reports)


def test_legitimate_multi_surface_and_repeated_action_workflows_remain_clean() -> None:
    multi_surface = scan_a2ui_duplex_path(_fixture("mcpdup001-origin-near-miss.json"))
    repeated = scan_a2ui_duplex_path(_fixture("mcpdup003-causality-near-miss.json"))
    assert multi_surface.verdict == "pass"
    assert multi_surface.statistics.surfaces_observed == 2
    assert repeated.verdict == "pass"
    assert repeated.statistics.actions_observed == 2


def test_transcript_array_order_does_not_create_false_causality() -> None:
    report = scan_a2ui_duplex_path(_fixture("mcpdup005-error-near-miss.json"))
    assert report.verdict == "pass"
    assert report.statistics.errors_observed == 1


def test_error_acknowledgement_on_another_surface_does_not_satisfy_receipt(
    tmp_path: Path,
) -> None:
    payload = _payload("mcpdup005-error-negative.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["message"]["updateDataModel"]["surfaceId"] = "other"
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert any(item.rule_id == "MCPDUP005" for item in report.findings)
    assert any("no later server acknowledgement" in item.evidence[0] for item in report.findings)


def test_duplicate_return_message_id_is_detected_without_hashing_payload_identity(
    tmp_path: Path,
) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    replay = deepcopy(transcript[-1])
    replay["sequence"] = 4
    replay["observed_at"] = "2026-01-01T12:00:03Z"
    replay["message"]["action"]["timestamp"] = "2026-01-01T12:00:03Z"
    transcript.append(replay)
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP003"}
    assert any("message_id is duplicated" in item.evidence[0] for item in report.findings)


def test_stale_revision_mutation_changes_only_origin_rule(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["origin"]["surfaceRevision"] = 1
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP001"}


def test_action_cannot_predate_the_active_surface_revision(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    action = transcript[-1]
    action["sequence"] = 4
    action["observed_at"] = "2026-01-01T12:00:04Z"
    action["origin"]["surfaceRevision"] = 3
    transcript.insert(
        2,
        {
            "sequence": 3,
            "direction": "server_to_client",
            "message_id": "s-data",
            "observed_at": "2026-01-01T12:00:03Z",
            "message": {
                "version": "v0.9",
                "updateDataModel": {"surfaceId": "main", "path": "/", "value": {}},
            },
        },
    )
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP003"}


def test_surface_clock_cannot_move_backward_before_an_action(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[0]["observed_at"] = "2026-01-01T12:00:05Z"
    transcript[1]["observed_at"] = "2026-01-01T12:00:01Z"
    transcript[2]["message"]["action"]["timestamp"] = "2026-01-01T12:00:02Z"
    transcript[2]["observed_at"] = "2026-01-01T12:00:03Z"
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP003"}
    assert any("surface observation time moves backward" in item.evidence[0] for item in report.findings)


def test_calendar_invalid_observed_at_is_unknown_not_an_input_error(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[0]["observed_at"] = "2026-99-99T12:00:00Z"
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unknown")]


def test_unsupported_action_schema_is_unknown_not_a_false_pass(tmp_path: Path) -> None:
    payload = _payload("mcpdup002-action-negative.json")
    contracts = payload["action_contracts"]
    assert isinstance(contracts, list)
    contracts[0]["context_schema"]["oneOf"] = [{"type": "object"}]
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unsupported")]


def test_nested_unsupported_schema_is_unknown_even_when_property_is_absent(
    tmp_path: Path,
) -> None:
    payload = _payload("mcpdup002-action-negative.json")
    contracts = payload["action_contracts"]
    assert isinstance(contracts, list)
    contracts[0]["context_schema"]["properties"]["optional"] = {
        "oneOf": [{"type": "string"}],
    }
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unsupported")]


def test_null_schema_type_is_unsupported_not_a_false_pass(tmp_path: Path) -> None:
    payload = _payload("mcpdup002-action-negative.json")
    contracts = payload["action_contracts"]
    assert isinstance(contracts, list)
    contracts[0]["context_schema"]["type"] = None
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unsupported")]


@pytest.mark.parametrize(
    "constraint",
    [
        {"const": 1},
        {"enum": [1]},
    ],
)
def test_action_schema_does_not_conflate_json_boolean_and_number(
    tmp_path: Path,
    constraint: dict[str, object],
) -> None:
    payload = _payload("mcpdup002-action-negative.json")
    contracts = payload["action_contracts"]
    assert isinstance(contracts, list)
    contracts[0]["context_schema"]["properties"]["amount"] = constraint
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["message"]["action"]["context"]["amount"] = True
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP002"}


def test_schema_budget_covers_absent_property_definitions(tmp_path: Path) -> None:
    payload = _payload("mcpdup002-action-negative.json")
    contracts = payload["action_contracts"]
    assert isinstance(contracts, list)
    contracts[0]["context_schema"]["properties"].update(
        {f"optional_{index}": {"type": "string"} for index in range(513)}
    )
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unsupported")]


def test_report_and_sarif_are_byte_stable_and_round_trip_strictly() -> None:
    path = _fixture("mcpdup003-causality-vulnerable.json")
    first = scan_a2ui_duplex_path(path)
    second = scan_a2ui_duplex_path(path)
    first_bytes = a2ui_duplex_report_json_bytes(first)
    assert first == second
    assert first_bytes == a2ui_duplex_report_json_bytes(second)
    assert first_bytes.endswith(b"\n")
    assert A2UIDuplexReport.model_validate_json(first_bytes, strict=True) == first
    assert render_a2ui_duplex_sarif(first) == render_a2ui_duplex_sarif(second)
    sarif = json.loads(render_a2ui_duplex_sarif(first))
    assert sarif["version"] == "2.1.0"
    assert {item["id"] for item in sarif["runs"][0]["tool"]["driver"]["rules"]} == {
        "MCPDUP000",
        "MCPDUP001",
        "MCPDUP002",
        "MCPDUP003",
        "MCPDUP004",
        "MCPDUP005",
        "MCPDUP006",
    }


def test_payload_values_and_error_text_do_not_leak_to_reports(tmp_path: Path) -> None:
    payload = _payload("mcpdup006-disclosure-vulnerable.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    model = transcript[-1]["metadata"]["a2uiClientDataModel"]["surfaces"]["main"]
    model["sensitive_note"] = "extremely-private-synthetic-value"
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    combined = a2ui_duplex_report_json_bytes(report) + render_a2ui_duplex_sarif(report)
    assert b"extremely-private-synthetic-value" not in combined
    assert b"sensitive_note" not in combined


def test_malformed_field_names_do_not_leak_through_validation_evidence(tmp_path: Path) -> None:
    payload = _payload()
    payload["synthetic_private_field_name"] = True
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    combined = a2ui_duplex_report_json_bytes(report) + render_a2ui_duplex_sarif(report)
    assert report.verdict == "unknown"
    assert b"synthetic_private_field_name" not in combined


def test_unsupported_message_name_is_not_reflected_into_evidence(tmp_path: Path) -> None:
    payload = _payload("mcpdup003-causality-negative.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["message"] = {
        "version": "v1.0",
        "SyntheticPrivateMessageName": {"value": "not-reportable"},
    }
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    combined = a2ui_duplex_report_json_bytes(report) + render_a2ui_duplex_sarif(report)
    assert report.verdict == "unknown"
    assert b"SyntheticPrivateMessageName" not in combined
    assert b"not-reportable" not in combined


def test_redaction_pseudonymizes_identifiers_in_json_and_sarif() -> None:
    report = scan_a2ui_duplex_path(
        _fixture("mcpdup001-origin-vulnerable.json"),
        redact=True,
    )
    assert report.redacted is True
    assert report.fixture_id.startswith("fixture-")
    assert report.producer_id.startswith("producer-")
    assert all(item.target.startswith("target-") for item in report.findings)
    combined = a2ui_duplex_report_json_bytes(report) + render_a2ui_duplex_sarif(report)
    assert b"mcpdup001-origin-vulnerable" not in combined
    assert b"synthetic-web-core" not in combined
    assert b"c-action" not in combined


def test_credential_looking_fixture_is_rejected_before_analysis(tmp_path: Path) -> None:
    payload = _payload()
    payload["api_key"] = "synthetic-placeholder"
    with pytest.raises(AgentUIInputError, match="credential-looking field"):
        scan_a2ui_duplex_path(_write_payload(tmp_path, payload))


def test_private_path_looking_fixture_value_is_rejected(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["message"]["action"]["context"]["amount"] = "/Users/example/private/value"
    with pytest.raises(AgentUIInputError, match="private path-looking value"):
        scan_a2ui_duplex_path(_write_payload(tmp_path, payload))


def test_absolute_json_pointer_is_not_mistaken_for_private_file_input(
    tmp_path: Path,
) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    binding = transcript[1]["message"]["updateComponents"]["components"][0]["action"]["event"]["context"][
        "amount"
    ]
    binding["path"] = "/Users/example/data"
    assert scan_a2ui_duplex_path(_write_payload(tmp_path, payload)).verdict == "pass"


def test_envelope_and_string_resource_limits_reject_unsafe_inputs(tmp_path: Path) -> None:
    payload = _payload()
    baseline = payload["transcript"][0]
    payload["transcript"] = [
        {**deepcopy(baseline), "sequence": index + 1, "message_id": f"server-{index}"} for index in range(513)
    ]
    with pytest.raises(AgentUIInputError, match="512 transcript envelopes"):
        scan_a2ui_duplex_path(_write_payload(tmp_path, payload, "too-many.json"))

    payload = _payload()
    payload["producer"]["producer_id"] = "x" * 16_385
    with pytest.raises(AgentUIInputError, match="fixture string exceeds"):
        scan_a2ui_duplex_path(_write_payload(tmp_path, payload, "long-string.json"))


def test_symlink_input_is_rejected() -> None:
    path = FIXTURE_ROOT / "fixture-link.json"
    try:
        path.symlink_to(_fixture("mcpdup001-origin-negative.json").resolve())
        with pytest.raises(AgentUIInputError, match="symlink"):
            scan_a2ui_duplex_path(path)
    finally:
        path.unlink(missing_ok=True)


def test_scanner_has_no_network_or_process_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"runtime effect attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert scan_a2ui_duplex_path(_fixture("mcpdup006-disclosure-negative.json")).verdict == "pass"


@pytest.mark.parametrize(
    ("contract", "model"),
    [
        ("fixture", A2UIDuplexFixture),
        ("disclosure-policy", DuplexDisclosurePolicy),
        ("report", A2UIDuplexReport),
    ],
)
def test_duplex_schema_commands_match_live_strict_models(
    contract: str,
    model: type[object],
) -> None:
    result = CliRunner().invoke(main, ["agent-ui", "duplex", "schema", contract])
    assert result.exit_code == 0, result.output
    schema = json.loads(result.output)
    assert schema == model.model_json_schema()  # type: ignore[attr-defined]
    assert schema["additionalProperties"] is False


def test_strict_fixture_schema_rejects_unknown_outer_fields() -> None:
    payload = _payload()
    payload["unsupported"] = True
    with pytest.raises(ValidationError):
        A2UIDuplexFixture.model_validate(payload, strict=True)


def test_action_cannot_carry_error_correlation_sidecar(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[-1]["correlation"] = {
        "sourceComponentId": "submit",
        "serverMessageId": "s-components",
    }
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert all(item.rule_id == "MCPDUP000" for item in report.findings)


def test_error_cannot_carry_action_origin_sidecar(tmp_path: Path) -> None:
    payload = _payload("mcpdup005-error-negative.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    transcript[2]["origin"] = {
        "surfaceRevision": 2,
        "componentRevision": 1,
        "serverMessageId": "s-components",
    }
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert all(item.rule_id == "MCPDUP000" for item in report.findings)


def test_empty_component_identifier_is_unknown_not_a_false_pass(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    components = transcript[1]["message"]["updateComponents"]["components"]
    components.append({"id": "", "component": "Card"})
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert all(item.rule_id == "MCPDUP000" for item in report.findings)


def test_component_action_event_rejects_unsupported_extra_fields(tmp_path: Path) -> None:
    payload = _payload()
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    event = transcript[1]["message"]["updateComponents"]["components"][0]["action"]["event"]
    event["unsupported"] = True
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert [(item.rule_id, item.status) for item in report.findings] == [("MCPDUP000", "unsupported")]


def test_v1_action_id_is_typed_even_when_no_response_is_requested(tmp_path: Path) -> None:
    payload = _payload("mcpdup003-causality-negative.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    action = transcript[-1]["message"]["action"]
    action["wantResponse"] = False
    action["actionId"] = {"malformed": True}
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "unknown"
    assert all(item.rule_id == "MCPDUP000" for item in report.findings)


def test_error_correlation_cannot_cross_a_recreated_surface_generation(
    tmp_path: Path,
) -> None:
    payload = _payload("mcpdup005-error-negative.json")
    transcript = payload["transcript"]
    assert isinstance(transcript, list)
    error = deepcopy(transcript[2])
    acknowledgement = deepcopy(transcript[3])
    payload["transcript"] = [
        transcript[0],
        transcript[1],
        {
            "sequence": 3,
            "direction": "server_to_client",
            "message_id": "s-delete",
            "observed_at": "2026-01-01T12:00:02Z",
            "message": {"version": "v0.9", "deleteSurface": {"surfaceId": "main"}},
        },
        {
            "sequence": 4,
            "direction": "server_to_client",
            "message_id": "s-create-new",
            "observed_at": "2026-01-01T12:00:03Z",
            "message": {
                "version": "v0.9",
                "createSurface": {
                    "surfaceId": "main",
                    "catalogId": "urn:a2ui:basic:v0.9",
                },
            },
        },
        {
            "sequence": 5,
            "direction": "server_to_client",
            "message_id": "s-components-new",
            "observed_at": "2026-01-01T12:00:04Z",
            "message": {
                "version": "v0.9",
                "updateComponents": {
                    "surfaceId": "main",
                    "components": [{"id": "status", "component": "Card"}],
                },
            },
        },
    ]
    error["sequence"] = 6
    error["observed_at"] = "2026-01-01T12:00:05Z"
    acknowledgement["sequence"] = 7
    acknowledgement["observed_at"] = "2026-01-01T12:00:06Z"
    payload["transcript"].extend([error, acknowledgement])
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP005"}


def test_explicit_empty_disclosure_allowlist_denies_nonempty_model(
    tmp_path: Path,
) -> None:
    payload = _payload("mcpdup006-disclosure-negative.json")
    rules = payload["disclosure_policy"]["surface_rules"]
    rules[0]["allowed_top_level_keys"] = []
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "fail"
    assert {item.rule_id for item in report.findings} == {"MCPDUP006"}


def test_omitted_disclosure_allowlist_preserves_explicit_unrestricted_policy(
    tmp_path: Path,
) -> None:
    payload = _payload("mcpdup006-disclosure-negative.json")
    rules = payload["disclosure_policy"]["surface_rules"]
    rules[0].pop("allowed_top_level_keys")
    report = scan_a2ui_duplex_path(_write_payload(tmp_path, payload))
    assert report.verdict == "pass"
    assert report.findings == []


def test_cli_writes_json_and_sarif_and_refuses_implicit_overwrite(tmp_path: Path) -> None:
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    args = [
        "agent-ui",
        "duplex",
        "scan",
        str(_fixture("mcpdup001-origin-negative.json")),
        "--json",
        str(json_path),
        "--sarif",
        str(sarif_path),
    ]
    runner = CliRunner()
    first = runner.invoke(main, args)
    assert first.exit_code == 0, first.output
    assert A2UIDuplexReport.model_validate_json(json_path.read_bytes(), strict=True).verdict == "pass"
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    second = runner.invoke(main, args)
    assert second.exit_code == 2
    assert "use --force" in second.output
    forced = runner.invoke(main, [*args, "--force"])
    assert forced.exit_code == 0, forced.output


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("mcpdup001-origin-negative.json", "pass"),
        ("mcpdup002-action-vulnerable.json", "fail"),
        ("mcpdup006-absent-policy-unknown.json", "unknown"),
    ],
)
def test_cli_smokes_valid_vulnerable_and_missing_policy(
    name: str,
    expected: str,
) -> None:
    result = CliRunner().invoke(main, ["agent-ui", "duplex", "scan", str(_fixture(name))])
    assert result.exit_code == (0 if expected == "pass" else 1)
    assert json.loads(result.output)["verdict"] == expected


def test_cli_smokes_malformed_unsupported_and_invalid_inputs(tmp_path: Path) -> None:
    malformed = _payload()
    malformed.pop("program_owned")
    malformed_result = CliRunner().invoke(
        main,
        ["agent-ui", "duplex", "scan", str(_write_payload(tmp_path, malformed, "malformed.json"))],
    )
    assert malformed_result.exit_code == 1
    assert json.loads(malformed_result.output)["verdict"] == "unknown"

    unsupported = _payload("mcpdup003-causality-negative.json")
    unsupported["transcript"][-1]["message"] = {
        "version": "v1.0",
        "functionResponse": {"functionCallId": "call-1", "call": "format", "value": "ok"},
    }
    unsupported_result = CliRunner().invoke(
        main,
        [
            "agent-ui",
            "duplex",
            "scan",
            str(_write_payload(tmp_path, unsupported, "unsupported.json")),
        ],
    )
    assert unsupported_result.exit_code == 1
    unsupported_report = json.loads(unsupported_result.output)
    assert unsupported_report["verdict"] == "unknown"
    assert unsupported_report["findings"][0]["status"] == "unsupported"

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    invalid_result = CliRunner().invoke(
        main,
        ["agent-ui", "duplex", "scan", str(invalid)],
    )
    assert invalid_result.exit_code == 2
    assert "invalid JSON duplex fixture" in invalid_result.output
