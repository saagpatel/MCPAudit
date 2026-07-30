from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import BaseModel

from mcp_audit.cli import main
from mcp_audit.subscription_stream_models import (
    MAX_DURATION_MS,
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    MAX_ID_CHARS,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_RESOURCE_SUBSCRIPTIONS,
    MAX_RESOURCE_URI_CHARS,
    MAX_STREAMS,
    SubscriptionReport,
    SubscriptionTrace,
)
from mcp_audit.subscription_stream_scanner import (
    SubscriptionStreamInputError,
    report_json_bytes,
    report_sarif,
    report_sarif_bytes,
    scan_subscription_stream_bytes,
    scan_subscription_stream_path,
)

FIXTURE_ROOT = Path("tests/fixtures/subscription_stream")
SCENARIOS = {
    "wrong-type": ("fail", "MCPSUB001"),
    "wrong-id": ("fail", "MCPSUB002"),
    "request-leak": ("fail", "MCPSUB003"),
    "wrong-resource-listener": ("fail", "MCPSUB004"),
    "post-close": ("fail", "MCPSUB005"),
    "valid-interleaving": ("fail", "MCPSUB002"),
    "reconnect": ("fail", "MCPSUB005"),
    "old-protocol": ("unknown", "MCPSUB007"),
    "truncated": ("unknown", "MCPSUB000"),
    "missing-ack": ("fail", "MCPSUB006"),
}
UNKNOWN_NEAR_MISSES = {"old-protocol", "truncated", "missing-ack"}


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / f"{name}.json"


def _payload(name: str) -> dict[str, Any]:
    loaded = json.loads(_fixture(name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _bytes(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _add_current_result_types(payload: dict[str, Any]) -> None:
    for event in payload["events"]:
        if event["lifecycle"] == "close":
            event["message"]["result"]["resultType"] = "complete"


def test_fixture_inventory_has_ten_vulnerable_negative_near_miss_triplets() -> None:
    fixture_names = {path.stem for path in FIXTURE_ROOT.glob("*.json")}
    assert len(fixture_names) == len(SCENARIOS) * 3
    for scenario in SCENARIOS:
        assert {
            f"{scenario}-vulnerable",
            f"{scenario}-negative",
            f"{scenario}-near-miss",
        }.issubset(fixture_names)


@pytest.mark.parametrize(("scenario", "expectation"), sorted(SCENARIOS.items()))
def test_vulnerable_controls_reach_the_expected_rule(
    scenario: str,
    expectation: tuple[str, str],
) -> None:
    expected_verdict, expected_rule = expectation
    report = scan_subscription_stream_path(_fixture(f"{scenario}-vulnerable"))
    assert report.verdict == expected_verdict
    assert expected_rule in {finding.rule_id for finding in report.findings}
    assert report.findings
    assert all(finding.evidence for finding in report.findings)
    assert all(finding.remediation for finding in report.findings)
    assert all(finding.assumptions for finding in report.findings)


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_negative_controls_are_current_complete_and_clean(scenario: str) -> None:
    report = scan_subscription_stream_path(_fixture(f"{scenario}-negative"))
    assert report.verdict == "pass"
    assert report.coverage == "complete"
    assert report.findings == []
    assert report.compatibility.status == "current_only"


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_near_misses_stay_clean_or_explicitly_unknown(scenario: str) -> None:
    report = scan_subscription_stream_path(_fixture(f"{scenario}-near-miss"))
    if scenario in UNKNOWN_NEAR_MISSES:
        assert report.verdict == "unknown"
        assert report.coverage == "unknown"
    else:
        assert report.verdict == "pass"
        assert report.coverage == "complete"
        assert report.findings == []


def test_report_is_deterministic_and_strictly_round_trips() -> None:
    path = _fixture("wrong-resource-listener-vulnerable")
    first = scan_subscription_stream_path(path)
    second = scan_subscription_stream_path(path)
    first_bytes = report_json_bytes(first)
    assert first == second
    assert first_bytes == report_json_bytes(second)
    assert first_bytes.endswith(b"\n")
    assert SubscriptionReport.model_validate_json(first_bytes, strict=True) == first


def test_jsonl_serialization_uses_header_then_bounded_event_lines(tmp_path: Path) -> None:
    payload = _payload("wrong-type-negative")
    events = payload.pop("events")
    raw = (
        "\n".join(json.dumps(item, sort_keys=True, separators=(",", ":")) for item in [payload, *events])
        + "\n"
    ).encode()
    report = scan_subscription_stream_bytes(raw)
    assert report.verdict == "pass"
    assert report.coverage == "complete"

    fixture = tmp_path / "trace.jsonl"
    fixture.write_bytes(raw)
    result = CliRunner().invoke(
        main,
        ["subscription-stream", "scan", str(fixture)],
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["input_sha256"] == report.input_sha256


def test_sarif_is_deterministic_complete_and_uses_only_synthetic_locations() -> None:
    report = scan_subscription_stream_path(_fixture("wrong-id-vulnerable"))
    first = report_sarif_bytes(report)
    assert first == report_sarif_bytes(report)
    payload = json.loads(first)
    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == 8
    assert [result["ruleId"] for result in run["results"]] == ["MCPSUB002"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "fixture://program-owned/"
    )
    assert str(_fixture("wrong-id-vulnerable").resolve()) not in first.decode()
    assert report_sarif(report) == payload


@pytest.mark.parametrize(
    ("name", "expected_exit", "expected_verdict"),
    [
        ("wrong-type-negative", 0, "pass"),
        ("wrong-type-vulnerable", 1, "fail"),
        ("wrong-id-vulnerable", 1, "fail"),
        ("request-leak-vulnerable", 1, "fail"),
        ("post-close-vulnerable", 1, "fail"),
        ("old-protocol-near-miss", 1, "unknown"),
        ("truncated-vulnerable", 1, "unknown"),
    ],
)
def test_offline_cli_json_smokes(
    name: str,
    expected_exit: int,
    expected_verdict: str,
) -> None:
    result = CliRunner().invoke(
        main,
        ["subscription-stream", "scan", str(_fixture(name))],
    )
    assert result.exit_code == expected_exit, result.output
    assert json.loads(result.output)["verdict"] == expected_verdict


def test_offline_cli_sarif_smoke() -> None:
    result = CliRunner().invoke(
        main,
        [
            "subscription-stream",
            "scan",
            str(_fixture("wrong-resource-listener-vulnerable")),
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "MCPSUB004"


@pytest.mark.parametrize(
    ("contract", "model"),
    [("trace", SubscriptionTrace), ("report", SubscriptionReport)],
)
def test_schema_command_matches_authoritative_strict_models(
    contract: str,
    model: type[BaseModel],
) -> None:
    result = CliRunner().invoke(main, ["subscription-stream", "schema", contract])
    assert result.exit_code == 0, result.output
    schema = json.loads(result.output)
    assert schema == model.model_json_schema()
    assert schema["additionalProperties"] is False


def test_malformed_json_returns_unknown_without_echoing_input() -> None:
    raw = b'{"schema_version":"mcpaudit.mcp-subscription-trace.v1","fixture_id":"broken",'
    report = scan_subscription_stream_bytes(raw)
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert [finding.rule_id for finding in report.findings] == ["MCPSUB000"]
    assert raw.decode() not in report_json_bytes(report).decode()


def test_malformed_cli_result_is_unknown_not_a_clean_or_usage_result(tmp_path: Path) -> None:
    fixture = tmp_path / "malformed.json"
    fixture.write_text('{"schema_version":', encoding="utf-8")
    result = CliRunner().invoke(main, ["subscription-stream", "scan", str(fixture)])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["verdict"] == "unknown"
    assert payload["coverage"] == "unknown"


def test_duplicate_json_keys_are_unknown() -> None:
    raw = (
        b'{"schema_version":"mcpaudit.mcp-subscription-trace.v1",'
        b'"schema_version":"mcpaudit.mcp-subscription-trace.v1"}'
    )
    report = scan_subscription_stream_bytes(raw)
    assert report.verdict == "unknown"
    assert "duplicate" in report.findings[0].evidence[0]


def test_harmless_interleaving_permutation_preserves_verdict_and_rules() -> None:
    original = _payload("valid-interleaving-near-miss")
    permuted = copy.deepcopy(original)
    order = [1, 0, 3, 2, 5, 4, 7, 6]
    events = [copy.deepcopy(original["events"][index]) for index in order]
    for index, event in enumerate(events):
        event["offset_ms"] = index
    permuted["events"] = events
    first = scan_subscription_stream_bytes(_bytes(original))
    second = scan_subscription_stream_bytes(_bytes(permuted))
    assert first.verdict == second.verdict == "pass"
    assert first.coverage == second.coverage == "complete"
    assert [finding.rule_id for finding in first.findings] == [finding.rule_id for finding in second.findings]
    assert first.stats == second.stats


def test_wrong_id_remains_a_violation_under_harmless_cross_stream_permutation() -> None:
    original = _payload("valid-interleaving-vulnerable")
    permuted = copy.deepcopy(original)
    order = [1, 0, 3, 2, 4, 6, 5]
    events = [copy.deepcopy(original["events"][index]) for index in order]
    for index, event in enumerate(events):
        event["offset_ms"] = index
    permuted["events"] = events
    reports = [
        scan_subscription_stream_bytes(_bytes(original)),
        scan_subscription_stream_bytes(_bytes(permuted)),
    ]
    assert {report.verdict for report in reports} == {"fail"}
    assert [{finding.rule_id for finding in report.findings} for report in reports] == [
        {"MCPSUB002"},
        {"MCPSUB002"},
    ]


def test_missing_ack_is_never_promoted_to_pass() -> None:
    report = scan_subscription_stream_path(_fixture("missing-ack-near-miss"))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert [(finding.rule_id, finding.outcome.value) for finding in report.findings] == [
        ("MCPSUB006", "unknown")
    ]


def test_legacy_events_are_classified_and_excluded_from_current_success() -> None:
    report = scan_subscription_stream_path(_fixture("old-protocol-vulnerable"))
    assert report.verdict == "unknown"
    assert report.compatibility.status == "mixed"
    assert report.compatibility.current_event_count > 0
    assert report.compatibility.legacy_event_count == 1
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB007"}


def test_resource_subresource_requires_an_explicit_listener_binding() -> None:
    payload = _payload("wrong-resource-listener-near-miss")
    payload["events"][2].pop("declared_resource_subscription")
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_request_only_trace_cannot_pass_without_subscription_evidence() -> None:
    payload = _payload("request-leak-negative")
    payload["events"] = [event for event in payload["events"] if event["stream_kind"] == "request"]
    payload["observed_duration_ms"] = len(payload["events"]) - 1
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_one_stream_identity_cannot_change_stream_kinds() -> None:
    payload = _payload("request-leak-negative")
    payload["events"][0]["stream_id"] = "tools-listener"
    payload["events"][1]["stream_id"] = "tools-listener"
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_reconnect_with_stale_subscription_id_is_unknown() -> None:
    payload = _payload("reconnect-near-miss")
    for event in payload["events"][3:]:
        event["request_id"] = "listen-old"
        event["subscription_id"] = "listen-old"
        message = event["message"]
        if message.get("id") == "listen-new":
            message["id"] = "listen-old"
        params = message.get("params")
        if isinstance(params, dict):
            metadata = params.get("_meta")
            if isinstance(metadata, dict):
                metadata["io.modelcontextprotocol/subscriptionId"] = "listen-old"
        result = message.get("result")
        if isinstance(result, dict):
            result["_meta"]["io.modelcontextprotocol/subscriptionId"] = "listen-old"
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_missing_notification_method_is_unknown_not_an_opt_in_violation() -> None:
    payload = _payload("wrong-type-vulnerable")
    payload["events"][2]["message"].pop("method")
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_malformed_current_protocol_messages_are_unknown() -> None:
    cases: list[dict[str, Any]] = []

    wrong_notification_version = _payload("wrong-type-negative")
    _add_current_result_types(wrong_notification_version)
    wrong_notification_version["events"][2]["message"]["jsonrpc"] = "1.0"
    cases.append(wrong_notification_version)

    request_shaped_acknowledgment = _payload("wrong-type-negative")
    _add_current_result_types(request_shaped_acknowledgment)
    request_shaped_acknowledgment["events"][1]["message"]["id"] = "unexpected"
    cases.append(request_shaped_acknowledgment)

    wrong_close_version = _payload("wrong-type-negative")
    _add_current_result_types(wrong_close_version)
    wrong_close_version["events"][3]["message"]["jsonrpc"] = "1.0"
    cases.append(wrong_close_version)

    missing_result_type = _payload("wrong-type-negative")
    _add_current_result_types(missing_result_type)
    missing_result_type["events"][3]["message"]["result"].pop("resultType")
    cases.append(missing_result_type)

    for payload in cases:
        report = scan_subscription_stream_bytes(_bytes(payload))
        assert report.verdict == "unknown"
        assert report.coverage == "unknown"
        assert "MCPSUB000" in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize(
    "mutation",
    ["wrong_jsonrpc", "forbidden_id", "wrong_direction", "non_string_method"],
)
def test_malformed_request_scoped_notifications_are_unknown(mutation: str) -> None:
    payload = _payload("request-leak-negative")
    message = payload["events"][1]["message"]
    if mutation == "wrong_jsonrpc":
        message["jsonrpc"] = "1.0"
    elif mutation == "forbidden_id":
        message["id"] = "unexpected"
    elif mutation == "wrong_direction":
        payload["events"][1]["direction"] = "client_to_server"
    elif mutation == "non_string_method":
        message["method"] = ["notifications/progress"]
    else:  # pragma: no cover - exhaustive guard for type checkers
        raise AssertionError(mutation)

    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert "MCPSUB000" in {finding.rule_id for finding in report.findings}


def test_subscription_non_string_method_is_unknown_not_a_crash() -> None:
    payload = _payload("wrong-type-negative")
    payload["events"][2]["message"]["method"] = ["notifications/tools/list_changed"]
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_checked_in_current_close_results_declare_result_type() -> None:
    close_count = 0
    for path in FIXTURE_ROOT.glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for event in payload["events"]:
            if event["lifecycle"] == "close":
                close_count += 1
                assert event["message"]["result"]["resultType"] == "complete"
    assert close_count > 0


def test_subscription_event_envelope_identifiers_cannot_drift() -> None:
    payload = _payload("wrong-type-negative")
    _add_current_result_types(payload)
    payload["events"][2]["request_id"] = "stale-listener"
    payload["events"][2]["subscription_id"] = "stale-listener"
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "fail"
    assert "MCPSUB002" in {finding.rule_id for finding in report.findings}


def test_wire_identifiers_do_not_treat_booleans_as_numeric_ids() -> None:
    payload = _payload("wrong-type-negative")
    _add_current_result_types(payload)
    for event in payload["events"]:
        event["request_id"] = 1
        event["subscription_id"] = 1
    payload["events"][0]["message"]["id"] = True
    payload["events"][1]["message"]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = True
    payload["events"][2]["message"]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = True
    payload["events"][3]["message"]["id"] = True
    payload["events"][3]["message"]["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = True
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "fail"
    assert "MCPSUB002" in {finding.rule_id for finding in report.findings}


def test_malformed_resource_uris_are_unknown() -> None:
    payload = _payload("wrong-resource-listener-negative")
    _add_current_result_types(payload)
    for event in payload["events"]:
        message = event.get("message") or {}
        params = message.get("params") or {}
        notifications = params.get("notifications")
        if isinstance(notifications, dict) and "resourceSubscriptions" in notifications:
            notifications["resourceSubscriptions"] = ["not a uri"]
        if message.get("method") == "notifications/resources/updated":
            params["uri"] = "not a uri"
            event["declared_resource_subscription"] = "not a uri"
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert "MCPSUB000" in {finding.rule_id for finding in report.findings}


def test_two_active_listeners_may_acknowledge_the_same_resource() -> None:
    payload = _payload("wrong-resource-listener-vulnerable")
    _add_current_result_types(payload)
    shared_resource = "file:///shared"
    for event in payload["events"]:
        message = event.get("message") or {}
        params = message.get("params") or {}
        notifications = params.get("notifications")
        if isinstance(notifications, dict) and "resourceSubscriptions" in notifications:
            notifications["resourceSubscriptions"] = [shared_resource]
        if message.get("method") == "notifications/resources/updated":
            params["uri"] = shared_resource
            event["declared_resource_subscription"] = shared_resource
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "pass"
    assert report.coverage == "complete"
    assert report.findings == []


def test_cancellation_terminates_only_its_subscription() -> None:
    baseline = _payload("wrong-type-negative")
    _add_current_result_types(baseline)
    opening, acknowledgment, notification, _close = baseline["events"]
    cancellation = {
        "stream_id": "tools-listener",
        "stream_kind": "subscription",
        "request_id": "listen-tools",
        "subscription_id": "listen-tools",
        "direction": "client_to_server",
        "lifecycle": "cancel",
        "protocol_version": "2026-07-28",
        "offset_ms": 2,
        "message": {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "listen-tools"},
        },
    }

    clean = copy.deepcopy(baseline)
    clean["events"] = [opening, acknowledgment, cancellation]
    clean["observed_duration_ms"] = 2
    clean_report = scan_subscription_stream_bytes(_bytes(clean))
    assert clean_report.verdict == "pass"
    assert clean_report.coverage == "complete"

    post_cancel = copy.deepcopy(clean)
    later_notification = copy.deepcopy(notification)
    later_notification["offset_ms"] = 3
    post_cancel["events"].append(later_notification)
    post_cancel["observed_duration_ms"] = 3
    post_cancel_report = scan_subscription_stream_bytes(_bytes(post_cancel))
    assert post_cancel_report.verdict == "fail"
    assert "MCPSUB005" in {finding.rule_id for finding in post_cancel_report.findings}

    malformed = copy.deepcopy(clean)
    malformed["events"][2]["message"]["jsonrpc"] = "1.0"
    malformed_report = scan_subscription_stream_bytes(_bytes(malformed))
    assert malformed_report.verdict == "unknown"
    assert malformed_report.coverage == "unknown"


def test_fixture_open_requests_nonblocking_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "trace.json"
    fixture.write_bytes(_bytes(_payload("wrong-type-negative")))
    opened: dict[str, int] = {}

    def capture_open(path: Path, flags: int) -> int:
        del path
        opened["flags"] = flags
        raise OSError("synthetic stop")

    monkeypatch.setattr("mcp_audit.subscription_stream_scanner.os.open", capture_open)
    with pytest.raises(SubscriptionStreamInputError):
        scan_subscription_stream_path(fixture)
    assert opened["flags"] & getattr(os, "O_NONBLOCK", 0)


def test_every_subscription_notification_is_checked_for_subscription_id() -> None:
    payload = _payload("wrong-type-vulnerable")
    payload["events"][2]["message"]["params"].pop("_meta")
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {
        "MCPSUB001",
        "MCPSUB002",
    }


def test_oversized_resource_update_uri_is_unknown() -> None:
    payload = _payload("wrong-resource-listener-near-miss")
    payload["events"][2]["message"]["params"]["uri"] = "file:///" + ("x" * MAX_RESOURCE_URI_CHARS)
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.coverage == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_invalid_date_shaped_protocol_version_is_unsupported_not_legacy() -> None:
    payload = _payload("wrong-type-negative")
    for event in payload["events"]:
        event["protocol_version"] = "2025-99-99"
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict == "unknown"
    assert report.compatibility.status == "unsupported"
    assert {finding.rule_id for finding in report.findings} == {"MCPSUB000"}


def test_reports_do_not_echo_message_data_ids_or_resource_uris() -> None:
    payload = _payload("wrong-resource-listener-vulnerable")
    payload["events"][4]["message"]["params"]["private"] = "SUPER-PRIVATE-SECRET"
    payload["events"][4]["declared_resource_subscription"] = "file:///SUPER-PRIVATE-SECRET"
    report_bytes = report_json_bytes(scan_subscription_stream_bytes(_bytes(payload)))
    assert b"SUPER-PRIVATE-SECRET" not in report_bytes
    assert b"file:///" not in report_bytes


def test_schema_validation_does_not_echo_arbitrary_field_names_or_schema_values() -> None:
    extra_field = _payload("wrong-type-negative")
    extra_field["SUPER-PRIVATE-SECRET"] = True
    extra_report = report_json_bytes(scan_subscription_stream_bytes(_bytes(extra_field)))
    assert b"SUPER-PRIVATE-SECRET" not in extra_report
    assert b"<field>" in extra_report

    wrong_schema = _payload("wrong-type-negative")
    wrong_schema["schema_version"] = "SUPER-PRIVATE-SECRET"
    schema_report = report_json_bytes(scan_subscription_stream_bytes(_bytes(wrong_schema)))
    assert b"SUPER-PRIVATE-SECRET" not in schema_report
    assert b'"fixture_schema_version":"unknown"' in schema_report


def test_scanner_has_no_network_or_process_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"runtime effect attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = scan_subscription_stream_path(_fixture("post-close-vulnerable"))
    assert report.verdict == "fail"


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    fixture = tmp_path / "trace.json"
    fixture.symlink_to(_fixture("wrong-type-negative").resolve())
    with pytest.raises(SubscriptionStreamInputError, match="symlink"):
        scan_subscription_stream_path(fixture)


def test_symlink_input_is_rejected_without_o_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "trace.json"
    fixture.symlink_to(_fixture("wrong-type-negative").resolve())
    monkeypatch.delattr("mcp_audit.subscription_stream_scanner.os.O_NOFOLLOW", raising=False)
    with pytest.raises(SubscriptionStreamInputError, match="symlink"):
        scan_subscription_stream_path(fixture)


def test_input_byte_limit_is_enforced_before_parsing(tmp_path: Path) -> None:
    fixture = tmp_path / "oversized.json"
    fixture.write_bytes(b"{" + (b" " * MAX_INPUT_BYTES) + b"}")
    with pytest.raises(SubscriptionStreamInputError, match="input limit"):
        scan_subscription_stream_path(fixture)
    with pytest.raises(SubscriptionStreamInputError, match="input limit"):
        scan_subscription_stream_bytes(fixture.read_bytes())


def test_json_depth_and_node_budgets_fail_closed() -> None:
    deep = (b'{"x":' * (MAX_JSON_DEPTH + 1)) + b"null" + (b"}" * (MAX_JSON_DEPTH + 1))
    deep_report = scan_subscription_stream_bytes(deep)
    assert deep_report.verdict == "unknown"
    assert str(MAX_JSON_DEPTH) in deep_report.findings[0].evidence[0]

    many_nodes = _bytes([None] * MAX_JSON_NODES)
    node_report = scan_subscription_stream_bytes(many_nodes)
    assert node_report.verdict == "unknown"
    assert str(MAX_JSON_NODES) in node_report.findings[0].evidence[0]


def test_stream_event_id_duration_and_event_size_limits_fail_closed() -> None:
    baseline = _payload("wrong-type-negative")

    too_many_streams = copy.deepcopy(baseline)
    opening = baseline["events"][0]
    too_many_streams["events"] = []
    for index in range(MAX_STREAMS + 1):
        event = copy.deepcopy(opening)
        event["stream_id"] = f"stream-{index}"
        event["request_id"] = f"listen-{index}"
        event["subscription_id"] = f"listen-{index}"
        event["message"]["id"] = f"listen-{index}"
        event["offset_ms"] = 0
        too_many_streams["events"].append(event)
    assert scan_subscription_stream_bytes(_bytes(too_many_streams)).verdict == "unknown"

    too_many_events = copy.deepcopy(baseline)
    event = copy.deepcopy(opening)
    event["offset_ms"] = 0
    too_many_events["events"] = [copy.deepcopy(event) for _ in range(MAX_EVENTS + 1)]
    assert scan_subscription_stream_bytes(_bytes(too_many_events)).verdict == "unknown"

    long_id = copy.deepcopy(baseline)
    long_id["events"][0]["stream_id"] = "s" * (MAX_ID_CHARS + 1)
    assert scan_subscription_stream_bytes(_bytes(long_id)).verdict == "unknown"

    long_duration = copy.deepcopy(baseline)
    long_duration["observed_duration_ms"] = MAX_DURATION_MS + 1
    assert scan_subscription_stream_bytes(_bytes(long_duration)).verdict == "unknown"

    large_event = copy.deepcopy(baseline)
    large_event["events"][2]["message"]["padding"] = "x" * MAX_EVENT_BYTES
    assert scan_subscription_stream_bytes(_bytes(large_event)).verdict == "unknown"


def test_resource_subscription_limit_fails_closed() -> None:
    payload = _payload("wrong-resource-listener-negative")
    resources = [f"file:///resource-{index}" for index in range(MAX_RESOURCE_SUBSCRIPTIONS + 1)]
    payload["events"][0]["message"]["params"]["notifications"]["resourceSubscriptions"] = resources
    payload["events"][1]["message"]["params"]["notifications"]["resourceSubscriptions"] = resources
    report = scan_subscription_stream_bytes(_bytes(payload))
    assert report.verdict != "pass"
    assert report.coverage == "unknown"
    assert "MCPSUB000" in {finding.rule_id for finding in report.findings}
