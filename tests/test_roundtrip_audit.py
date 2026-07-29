from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mcp_audit.cli import main
from mcp_audit.roundtrip_models import REPORT_SCHEMA, RoundTripReport
from mcp_audit.roundtrip_scanner import (
    MAXIMUM_BYTES,
    MAXIMUM_DEPTH,
    MAXIMUM_EVENTS,
    MAXIMUM_STRING_BYTES,
    RoundTripInputError,
    report_json_bytes,
    scan_roundtrip_path,
)
from mcp_audit.sarif import SarifGenerator

FIXTURE_ROOT = Path("tests/fixtures/roundtrip")
VULNERABLE_FIXTURES = {
    "mcprt000-vulnerable.json": ("MCPRT000", "UNSUPPORTED", "unsupported"),
    **{f"mcprt{rule:03d}-vulnerable.json": (f"MCPRT{rule:03d}", "FAIL", "fail") for rule in range(1, 7)},
}
EXPECTED_CONTROLS = {
    "mcprt000-negative.json": ("MCPRT000", "PASS"),
    "mcprt000-near-miss.jsonl": ("MCPRT000", "PASS"),
    "mcprt001-negative.json": ("MCPRT001", "PASS"),
    "mcprt001-near-miss.json": ("MCPRT001", "PASS"),
    "mcprt002-negative.json": ("MCPRT002", "PASS"),
    "mcprt002-near-miss.json": ("MCPRT002", "UNKNOWN"),
    "mcprt003-negative.json": ("MCPRT003", "PASS"),
    "mcprt003-near-miss.json": ("MCPRT003", "PASS"),
    "mcprt004-negative.json": ("MCPRT004", "PASS"),
    "mcprt004-near-miss.jsonl": ("MCPRT004", "PASS"),
    "mcprt005-negative.json": ("MCPRT005", "PASS"),
    "mcprt005-near-miss.json": ("MCPRT005", "UNKNOWN"),
    "mcprt006-negative.jsonl": ("MCPRT006", "PASS"),
    "mcprt006-near-miss.json": ("MCPRT006", "NOT_APPLICABLE"),
}


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / name


def _status(report: RoundTripReport, rule_id: str) -> str:
    return next(item.status for item in report.rules if item.rule_id == rule_id)


def _payload(name: str) -> dict[str, object]:
    value = json.loads(_fixture(name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_fixture_inventory_has_seven_vulnerable_negative_near_miss_triplets() -> None:
    for rule in range(7):
        prefix = f"mcprt{rule:03d}-"
        members = sorted(path.name for path in FIXTURE_ROOT.iterdir() if path.name.startswith(prefix))
        assert len(members) == 3
        assert any("-vulnerable." in name for name in members)
        assert any("-negative." in name for name in members)
        assert any("-near-miss." in name for name in members)


@pytest.mark.parametrize(("name", "expected"), VULNERABLE_FIXTURES.items())
def test_each_vulnerable_control_fires_its_stable_rule(
    name: str,
    expected: tuple[str, str, str],
) -> None:
    rule_id, status, verdict = expected
    report = scan_roundtrip_path(_fixture(name))
    assert report.verdict == verdict
    assert _status(report, rule_id) == status
    if status == "FAIL":
        assert [item.rule_id for item in report.rules if item.status == "FAIL"] == [rule_id]
    finding = next(item for item in report.findings if item.status == status)
    assert finding.rule_id == rule_id
    assert finding.evidence
    assert finding.remediation
    assert all("synthetic-value-must-not-echo" not in item.evidence for item in report.findings)


@pytest.mark.parametrize(
    ("name", "expected"),
    EXPECTED_CONTROLS.items(),
)
def test_negative_and_near_miss_controls_are_distinguished(
    name: str,
    expected: tuple[str, str],
) -> None:
    rule_id, status = expected
    report = scan_roundtrip_path(_fixture(name))
    assert _status(report, rule_id) == status
    assert not any(item.status == "FAIL" for item in report.rules)


def test_report_is_byte_stable_and_strictly_round_trips() -> None:
    path = _fixture("mcprt004-negative.json")
    first = scan_roundtrip_path(path)
    second = scan_roundtrip_path(path)
    assert first == second
    first_bytes = report_json_bytes(first)
    assert first_bytes == report_json_bytes(second)
    assert first_bytes.endswith(b"\n")
    assert RoundTripReport.model_validate_json(first_bytes, strict=True) == first
    assert b"observed_at" not in first_bytes
    assert str(path.resolve()).encode() not in first_bytes


def test_report_has_narrow_claim_ceiling_and_recorded_limits() -> None:
    report = scan_roundtrip_path(_fixture("mcprt001-negative.json"))
    assert report.schema_version == REPORT_SCHEMA
    assert report.limits.maximum_bytes == MAXIMUM_BYTES
    assert report.limits.maximum_depth == MAXIMUM_DEPTH
    assert report.limits.maximum_events == MAXIMUM_EVENTS
    assert report.limits.maximum_string_bytes == MAXIMUM_STRING_BYTES
    unsupported = " ".join(report.unsupported_claims)
    assert "Real-host security" in unsupported
    assert "Cryptographic" in unsupported
    assert "Interoperability" in unsupported


def test_scanner_has_no_network_or_process_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"runtime effect attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert scan_roundtrip_path(_fixture("mcprt003-vulnerable.json")).verdict == "fail"
    assert scan_roundtrip_path(_fixture("mcprt005-negative.json")).verdict == "pass"


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("malformed.json", "invalid JSON trace"),
        ("duplicate-key.json", "invalid JSON trace"),
        ("out-of-order.json", "strictly increasing"),
    ],
)
def test_malformed_duplicate_and_out_of_order_inputs_are_rejected(
    name: str,
    message: str,
) -> None:
    with pytest.raises(RoundTripInputError, match=message):
        scan_roundtrip_path(_fixture(name))


def test_unsupported_revision_is_structured_and_never_clean() -> None:
    report = scan_roundtrip_path(_fixture("unsupported.json"))
    assert report.verdict == "unsupported"
    assert {item.status for item in report.rules} == {"UNSUPPORTED"}
    assert report.findings[0].rule_id == "MCPRT000"
    assert report.findings[0].status == "UNSUPPORTED"


def test_partial_round_trip_is_unknown_not_clean(tmp_path: Path) -> None:
    payload = _payload("mcprt001-negative.json")
    payload["events"] = payload["events"][:1]  # type: ignore[index]
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert report.verdict == "unknown"
    assert _status(report, "MCPRT004") == "UNKNOWN"


def test_stdio_duplicate_request_ids_are_reported(tmp_path: Path) -> None:
    payload = _payload("mcprt001-negative.json")
    duplicate = json.loads(json.dumps(payload["events"][0]))  # type: ignore[index]
    duplicate["sequence"] = 1
    payload["events"][1]["sequence"] = 2  # type: ignore[index]
    payload["events"] = [payload["events"][0], duplicate, payload["events"][1]]  # type: ignore[index]
    path = tmp_path / "stdio-duplicate.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT006") == "FAIL"


def test_stdio_broken_stream_event_is_unsupported_not_clean(tmp_path: Path) -> None:
    payload = _payload("mcprt001-negative.json")
    payload["events"] = [
        payload["events"][0],  # type: ignore[index]
        {
            "sequence": 1,
            "kind": "stream_broken",
            "observed_at": "2026-07-28T10:00:01Z",
            "request_id": 1,
        },
    ]
    path = tmp_path / "stdio-stream-broken.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert report.verdict == "unsupported"
    assert _status(report, "MCPRT006") == "UNSUPPORTED"


def test_credential_looking_input_is_rejected_without_echo() -> None:
    with pytest.raises(RoundTripInputError) as captured:
        scan_roundtrip_path(_fixture("credential-looking.json"))
    message = str(captured.value)
    assert "credential-looking" in message
    assert "synthetic-value-must-not-echo" not in message


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    link = tmp_path / "fixture.json"
    link.symlink_to(_fixture("mcprt001-negative.json").resolve())
    with pytest.raises(RoundTripInputError, match="symlink"):
        scan_roundtrip_path(link)


def test_byte_limit_is_enforced_before_parse(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAXIMUM_BYTES + 1))
    with pytest.raises(RoundTripInputError, match="exceeds"):
        scan_roundtrip_path(path)


def test_depth_limit_is_enforced_before_model_validation(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * (MAXIMUM_DEPTH + 1) + "]" * (MAXIMUM_DEPTH + 1), encoding="utf-8")
    with pytest.raises(RoundTripInputError, match="nesting"):
        scan_roundtrip_path(path)


def test_event_and_string_limits_are_enforced(tmp_path: Path) -> None:
    payload = _payload("mcprt001-negative.json")
    event = payload["events"][0]  # type: ignore[index]
    payload["events"] = [
        {**event, "sequence": sequence}  # type: ignore[arg-type]
        for sequence in range(MAXIMUM_EVENTS + 1)
    ]
    events_path = tmp_path / "too-many-events.json"
    events_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RoundTripInputError, match="events"):
        scan_roundtrip_path(events_path)

    payload = _payload("mcprt001-negative.json")
    payload["padding"] = "x" * (MAXIMUM_STRING_BYTES + 1)
    string_path = tmp_path / "long-string.json"
    string_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RoundTripInputError, match="JSON string exceeds"):
        scan_roundtrip_path(string_path)


def test_naive_observation_timestamp_is_rejected_not_crashed(tmp_path: Path) -> None:
    payload = _payload("mcprt005-negative.json")
    payload["events"][2]["observed_at"] = "2026-07-28T10:00:02"  # type: ignore[index]
    path = tmp_path / "naive-time.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RoundTripInputError, match="timezone"):
        scan_roundtrip_path(path)


def test_http_version_rejection_requires_observed_400(tmp_path: Path) -> None:
    payload = _payload("mcprt001-near-miss.json")
    payload["transport"] = "streamable-http"
    request = payload["events"][0]  # type: ignore[index]
    request["http"] = {  # type: ignore[index]
        "headers": {
            "MCP-Protocol-Version": "2099-01-01",
            "Mcp-Method": "tools/list",
        }
    }
    path = tmp_path / "missing-http-status.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT001") == "FAIL"


def test_discovery_agrees_with_explicit_rejection_of_unadvertised_version(
    tmp_path: Path,
) -> None:
    payload = _payload("mcprt002-negative.json")
    request_meta = payload["events"][2]["message"]["params"]["_meta"]  # type: ignore[index]
    request_meta["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"  # type: ignore[index]
    payload["events"][3]["message"].pop("result")  # type: ignore[index]
    payload["events"][3]["message"]["error"] = {  # type: ignore[index]
        "code": -32022,
        "message": "unsupported revision",
        "data": {"requested": "2099-01-01", "supported": ["2026-07-28"]},
    }
    path = tmp_path / "discovery-rejection.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT001") == "PASS"
    assert _status(report, "MCPRT002") == "PASS"


def test_empty_discovery_version_advertisement_fails(tmp_path: Path) -> None:
    payload = _payload("mcprt002-near-miss.json")
    payload["events"][1]["message"]["result"]["supportedVersions"] = []  # type: ignore[index]
    path = tmp_path / "empty-discovery-versions.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT002") == "FAIL"


def test_expired_trusted_witness_is_a_replay_boundary_failure(tmp_path: Path) -> None:
    payload = _payload("mcprt005-negative.json")
    witness = payload["witnesses"][0]  # type: ignore[index]
    witness["expires_at"] = "2026-07-28T10:00:01Z"  # type: ignore[index]
    path = tmp_path / "expired.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT005") == "FAIL"


def test_mrtr_response_key_mismatch_is_not_silently_accepted(tmp_path: Path) -> None:
    payload = _payload("mcprt004-negative.json")
    retry_params = payload["events"][2]["message"]["params"]  # type: ignore[index]
    retry_params["inputResponses"] = {"other": {"action": "accept"}}  # type: ignore[index]
    path = tmp_path / "bad-correlation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT004") == "FAIL"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "prompts/get"),
        ("arguments", {"city": "pdx"}),
    ],
)
def test_request_state_method_and_parameter_replay_boundaries_fire(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = _payload("mcprt005-negative.json")
    retry_message = payload["events"][2]["message"]  # type: ignore[index]
    if field == "method":
        retry_message["method"] = value  # type: ignore[index]
    else:
        retry_message["params"]["arguments"] = value  # type: ignore[index]
    path = tmp_path / f"state-{field}-replay.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT005") == "FAIL"


def test_malformed_input_requests_are_not_treated_as_state_only_mrtr(
    tmp_path: Path,
) -> None:
    payload = _payload("mcprt004-negative.json")
    result = payload["events"][1]["message"]["result"]  # type: ignore[index]
    result["inputRequests"] = ["not", "a", "mapping"]  # type: ignore[index]
    path = tmp_path / "malformed-input-requests.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT004") == "FAIL"


def test_unsupported_mrtr_input_method_fails_without_crashing(tmp_path: Path) -> None:
    payload = _payload("mcprt004-negative.json")
    input_request = payload["events"][1]["message"]["result"]["inputRequests"][  # type: ignore[index]
        "confirm"
    ]
    input_request["method"] = "custom/ask"  # type: ignore[index]
    path = tmp_path / "unsupported-input-method.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_roundtrip_path(path)
    assert _status(report, "MCPRT004") == "FAIL"


def test_observed_custom_tool_header_must_match_body_argument(tmp_path: Path) -> None:
    payload = _payload("mcprt003-negative.json")
    call = payload["events"][0]  # type: ignore[index]
    final = payload["events"][1]  # type: ignore[index]
    call["sequence"] = 2  # type: ignore[index]
    call["message"]["id"] = 2  # type: ignore[index]
    call["message"]["params"]["arguments"] = {"region": "us-west1"}  # type: ignore[index]
    call["http"]["headers"]["Mcp-Param-Region"] = "us-west1"  # type: ignore[index]
    final["sequence"] = 3  # type: ignore[index]
    final["message"]["id"] = 2  # type: ignore[index]
    payload["events"] = [
        {
            "sequence": 0,
            "kind": "client_request",
            "observed_at": "2026-07-28T09:59:58Z",
            "principal": "alice",
            "message": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
            "http": {
                "headers": {
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/list",
                }
            },
        },
        {
            "sequence": 1,
            "kind": "server_response",
            "observed_at": "2026-07-28T09:59:59Z",
            "message": {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "resultType": "complete",
                    "tools": [
                        {
                            "name": "weather",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "region": {
                                        "type": "string",
                                        "x-mcp-header": "Region",
                                    }
                                },
                            },
                        }
                    ],
                },
            },
            "http": {"status": 200, "headers": {}},
        },
        call,
        final,
    ]
    clean_path = tmp_path / "custom-header-clean.json"
    clean_path.write_text(json.dumps(payload), encoding="utf-8")
    assert _status(scan_roundtrip_path(clean_path), "MCPRT003") == "PASS"

    call["http"]["headers"]["Mcp-Param-Region"] = "eu-west1"  # type: ignore[index]
    mismatch_path = tmp_path / "custom-header-mismatch.json"
    mismatch_path.write_text(json.dumps(payload), encoding="utf-8")
    assert _status(scan_roundtrip_path(mismatch_path), "MCPRT003") == "FAIL"


def test_sarif_projection_uses_existing_shape_and_stable_fingerprints() -> None:
    report = scan_roundtrip_path(_fixture("mcprt003-vulnerable.json"))
    first = SarifGenerator().generate_roundtrip(report)
    second = SarifGenerator().generate_roundtrip(report)
    assert first == second
    run = first["runs"][0]
    assert first["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == 7
    assert run["results"][0]["ruleId"] == "MCPRT003"
    assert run["results"][0]["partialFingerprints"]["mcpAuditStableId"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "mcpaudit://synthetic/"
    )


@pytest.mark.parametrize(
    ("name", "exit_code", "verdict"),
    [
        ("mcprt004-negative.json", 0, "pass"),
        ("mcprt003-vulnerable.json", 1, "fail"),
        ("malformed.json", 2, None),
        ("unsupported.json", 1, "unsupported"),
    ],
)
def test_cli_exit_semantics(name: str, exit_code: int, verdict: str | None) -> None:
    result = CliRunner().invoke(main, ["roundtrip", "scan", str(_fixture(name))])
    assert result.exit_code == exit_code
    if verdict is not None:
        assert json.loads(result.output)["verdict"] == verdict


def test_cli_machine_output_is_stable_and_sarif_is_compatible(tmp_path: Path) -> None:
    runner = CliRunner()
    args = ["roundtrip", "scan", str(_fixture("mcprt003-vulnerable.json"))]
    first = runner.invoke(main, args)
    second = runner.invoke(main, args)
    assert first.exit_code == second.exit_code == 1
    assert first.output == second.output

    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    result = runner.invoke(
        main,
        [
            "roundtrip",
            "scan",
            str(_fixture("mcprt003-vulnerable.json")),
            "--json",
            str(json_path),
            "--sarif",
            str(sarif_path),
        ],
    )
    assert result.exit_code == 1
    assert json.loads(json_path.read_text())["schema_version"] == REPORT_SCHEMA
    assert json.loads(sarif_path.read_text())["version"] == "2.1.0"


def test_cli_refuses_output_alias_and_existing_file(tmp_path: Path) -> None:
    runner = CliRunner()
    fixture = _fixture("mcprt001-negative.json")
    alias = runner.invoke(
        main,
        ["roundtrip", "scan", str(fixture), "--json", str(fixture)],
    )
    assert alias.exit_code == 2
    output = tmp_path / "report.json"
    output.write_text("keep", encoding="utf-8")
    existing = runner.invoke(
        main,
        ["roundtrip", "scan", str(fixture), "--json", str(output)],
    )
    assert existing.exit_code == 2
    assert output.read_text(encoding="utf-8") == "keep"


def test_authoritative_schemas_are_strict() -> None:
    runner = CliRunner()
    for contract in ("trace", "jsonl-manifest", "request-state-witness", "report"):
        result = runner.invoke(main, ["roundtrip", "schema", contract])
        assert result.exit_code == 0
        schema = json.loads(result.output)
        assert schema["additionalProperties"] is False
    report_schema = json.loads(runner.invoke(main, ["roundtrip", "schema", "report"]).output)
    with pytest.raises(ValidationError):
        RoundTripReport.model_validate(
            {
                "schema_version": REPORT_SCHEMA,
                "unexpected": True,
            },
            strict=True,
        )
    assert report_schema["properties"]["schema_version"]["const"] == REPORT_SCHEMA
