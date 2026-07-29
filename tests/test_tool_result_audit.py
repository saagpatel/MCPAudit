from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from typing import Any
from urllib import request as urllib_request

import pytest
from click.testing import CliRunner

from mcp_audit import tool_result_scanner
from mcp_audit.cli import main
from mcp_audit.tool_result_models import ToolResultFixture, ToolResultReport
from mcp_audit.tool_result_scanner import report_json_bytes, scan_tool_result_bytes

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tool_result"

VULNERABLE_EXPECTATIONS = {
    "schema-mismatch": ("fail", "MCPTR001"),
    "composition-ref": ("unknown", "MCPTR000"),
    "resource-limit": ("unknown", "MCPTR000"),
    "correlation": ("fail", "MCPTR002"),
    "channel-divergence": ("unknown", "MCPTR005"),
    "policy-contradiction": ("fail", "MCPTR005"),
    "metadata-reflection": ("fail", "MCPTR006"),
    "malformed-error": ("fail", "MCPTR003"),
    "incomplete-list": ("unknown", "MCPTR000"),
}


def _fixture_bytes(category: str, variant: str) -> bytes:
    return (FIXTURE_DIR / f"{category}-{variant}.json").read_bytes()


def _fixture_payload(category: str = "schema-mismatch", variant: str = "negative") -> dict[str, Any]:
    return json.loads(_fixture_bytes(category, variant))


def _scan_payload(payload: dict[str, Any]) -> ToolResultReport:
    return scan_tool_result_bytes(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )


@pytest.mark.parametrize(
    ("category", "expected_verdict", "expected_rule"),
    [(category, expected[0], expected[1]) for category, expected in VULNERABLE_EXPECTATIONS.items()],
)
def test_vulnerable_fixture_triplets_fire_expected_rule(
    category: str,
    expected_verdict: str,
    expected_rule: str,
) -> None:
    report = scan_tool_result_bytes(_fixture_bytes(category, "vulnerable"))
    assert report.verdict == expected_verdict
    assert expected_rule in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize("category", sorted(VULNERABLE_EXPECTATIONS))
@pytest.mark.parametrize("variant", ["negative", "near-miss"])
def test_negative_and_near_miss_fixture_triplets_pass(category: str, variant: str) -> None:
    report = scan_tool_result_bytes(_fixture_bytes(category, variant))
    assert report.verdict == "pass"
    assert report.coverage == "complete"
    assert report.findings == []


def test_local_composition_and_ref_are_validated_as_json_schema_2020_12() -> None:
    report = scan_tool_result_bytes(_fixture_bytes("composition-ref", "near-miss"))
    assert report.verdict == "pass"


def test_external_ref_is_unknown_without_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(urllib_request, "urlopen", deny_network)
    report = scan_tool_result_bytes(_fixture_bytes("composition-ref", "vulnerable"))
    assert report.verdict == "unknown"
    assert report.findings[0].rule_id == "MCPTR000"


def test_pattern_validation_is_explicitly_unsupported() -> None:
    payload = _fixture_payload()
    tool = payload["toolsList"]["response"]["result"]["tools"][0]
    tool["outputSchema"] = {"type": "string", "pattern": "^(a+)+$"}
    payload["calls"][0]["response"]["result"]["structuredContent"] = "aaaa"
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_current_revision_result_discriminator_is_required() -> None:
    payload = _fixture_payload()
    del payload["calls"][0]["response"]["result"]["resultType"]
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR003" in {finding.rule_id for finding in report.findings}


def test_current_revision_list_cache_fields_are_required() -> None:
    payload = _fixture_payload()
    del payload["toolsList"]["response"]["result"]["ttlMs"]
    del payload["toolsList"]["response"]["result"]["cacheScope"]
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert [finding.rule_id for finding in report.findings].count("MCPTR003") == 2


def test_single_paginated_list_page_is_incomplete_coverage() -> None:
    payload = _fixture_payload()
    payload["toolsList"]["response"]["result"]["nextCursor"] = "next-page"
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert report.coverage == "incomplete"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_paginated_list_does_not_claim_called_tool_is_absent() -> None:
    payload = _fixture_payload()
    payload["toolsList"]["response"]["result"]["tools"] = []
    payload["toolsList"]["response"]["result"]["nextCursor"] = "next-page"
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_malformed_next_cursor_is_a_result_shape_violation() -> None:
    payload = _fixture_payload()
    payload["toolsList"]["response"]["result"]["nextCursor"] = None
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR003" in {finding.rule_id for finding in report.findings}


def test_unsupported_revision_is_unknown_without_applying_current_shapes() -> None:
    payload = _fixture_payload()
    payload["protocolRevision"] = "2025-11-25"
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert report.coverage == "unsupported"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_resource_links_and_embedded_resources_have_independent_bounded_shapes() -> None:
    payload = _fixture_payload()
    call = payload["calls"][0]
    call["response"]["result"]["content"].extend(
        [
            {
                "type": "resource_link",
                "uri": "file:///synthetic/report.txt",
                "name": "report.txt",
                "mimeType": "text/plain",
                "size": 12.5,
                "icons": [{"src": "data:image/png;base64,AA==", "theme": "dark"}],
            },
            {
                "type": "resource",
                "resource": {
                    "uri": "urn:mcpaudit:synthetic:report",
                    "mimeType": "text/plain",
                    "text": "fixture only",
                },
                "annotations": {"audience": ["assistant"], "priority": 0.5},
            },
        ]
    )
    call["channelPolicy"]["requiredChannels"].extend(["resource_link", "embedded_resource"])
    report = _scan_payload(payload)
    assert report.verdict == "pass"


@pytest.mark.parametrize(
    "block",
    [
        {
            "type": "resource_link",
            "uri": "file:///synthetic/report.txt",
            "name": "report.txt",
            "description": 42,
        },
        {
            "type": "resource_link",
            "uri": "file:///synthetic/report.txt",
            "name": "report.txt",
            "icons": [{"src": 42}],
        },
        {
            "type": "resource",
            "resource": {
                "uri": "urn:mcpaudit:synthetic:report",
                "mimeType": 42,
                "text": "fixture only",
            },
        },
    ],
)
def test_malformed_optional_resource_fields_are_shape_violations(
    block: dict[str, Any],
) -> None:
    payload = _fixture_payload()
    payload["calls"][0]["response"]["result"]["content"] = [block]
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR004" in {finding.rule_id for finding in report.findings}


def test_malformed_resource_link_is_not_accepted_as_another_channel() -> None:
    payload = _fixture_payload()
    call = payload["calls"][0]
    call["response"]["result"]["content"] = [{"type": "resource_link", "uri": "file:///synthetic/report.txt"}]
    call["channelPolicy"] = {"requiredChannels": ["resource_link", "structuredContent"]}
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR004" in {finding.rule_id for finding in report.findings}


def test_content_resource_does_not_substitute_for_required_structured_content() -> None:
    payload = _fixture_payload("schema-mismatch", "near-miss")
    call = payload["calls"][0]
    del call["response"]["result"]["structuredContent"]
    call["response"]["result"]["content"] = [
        {
            "type": "resource",
            "resource": {"uri": "urn:synthetic:data", "text": '{"temperature":22}'},
        }
    ]
    call["channelPolicy"] = {
        "requiredChannels": ["structuredContent", "embedded_resource"],
        "representation": "independent",
    }
    report = _scan_payload(payload)
    rules = {finding.rule_id for finding in report.findings}
    assert report.verdict == "fail"
    assert {"MCPTR001", "MCPTR004"} <= rules


def test_unsupported_request_param_extension_is_unknown_not_a_shape_failure() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["request"]["params"]["com.example/extension"] = {"fixture": True}
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_total_decoded_resource_payload_is_bounded() -> None:
    payload = _fixture_payload()
    chunk = base64.b64encode(b"x" * 40_000).decode()
    payload["calls"][0]["response"]["result"]["content"] = [
        {"type": "image", "data": chunk, "mimeType": "image/png"} for _ in range(7)
    ]
    payload["calls"][0]["channelPolicy"] = {"requiredChannels": ["content", "structuredContent"]}
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert "MCPTR000" in {finding.rule_id for finding in report.findings}


def test_over_limit_content_count_is_unknown_without_false_channel_failure() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["response"]["result"]["content"] = [
        {"type": "text", "text": "bounded"} for _ in range(65)
    ]
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_metadata_sentinel_is_redacted_from_finding_and_report_bytes() -> None:
    input_bytes = _fixture_bytes("metadata-reflection", "vulnerable")
    assert b"PRIVATE_META_SENTINEL_42" in input_bytes
    report = scan_tool_result_bytes(input_bytes)
    output = report_json_bytes(report)
    assert report.verdict == "fail"
    assert b"PRIVATE_META_SENTINEL_42" not in output
    assert b"com.example/privateToken" not in output


def test_dual_channels_require_explicit_representation_even_with_channel_requirements() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["channelPolicy"] = {"requiredChannels": ["content", "structuredContent"]}
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR005"}


def test_json_equivalence_does_not_treat_boolean_as_number() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["response"]["result"]["content"][0]["text"] = "true"
    payload["calls"][0]["response"]["result"]["structuredContent"] = 1
    payload["calls"][0]["channelPolicy"] = {
        "requiredChannels": ["content", "structuredContent"],
        "representation": "json_equivalent",
        "textContentIndex": 0,
    }
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR005"}


def test_json_equivalence_rejects_duplicate_object_keys() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["response"]["result"]["content"][0]["text"] = '{"temperature":22,"temperature":23}'
    payload["calls"][0]["response"]["result"]["structuredContent"] = {"temperature": 23}
    payload["calls"][0]["channelPolicy"] = {
        "requiredChannels": ["content", "structuredContent"],
        "representation": "json_equivalent",
        "textContentIndex": 0,
    }
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR005"}


def test_metadata_confined_to_meta_is_not_echoed() -> None:
    input_bytes = _fixture_bytes("metadata-reflection", "near-miss")
    report = scan_tool_result_bytes(input_bytes)
    assert report.verdict == "pass"
    assert b"PRIVATE_META_SENTINEL_42" not in report_json_bytes(report)


def test_private_metadata_value_cannot_leak_through_fixture_id() -> None:
    payload = _fixture_payload()
    private_value = "private-meta-sentinel"
    payload["fixtureId"] = private_value
    payload["applicationOnlyMetadataKeys"] = ["com.example/privateToken"]
    payload["calls"][0]["response"]["result"]["_meta"] = {"com.example/privateToken": private_value}
    report = _scan_payload(payload)
    output = report_json_bytes(report)
    assert report.verdict == "pass"
    assert report.fixture_id == "redacted"
    assert private_value.encode() not in output


def test_existing_process_alarm_makes_validation_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tool_result_scanner.signal, "getitimer", lambda timer: (0.5, 0.0))
    report = scan_tool_result_bytes(_fixture_bytes("schema-mismatch", "near-miss"))
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_failed_validation_timer_install_restores_signal_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_handler = object()
    installed_handlers: list[object] = []

    monkeypatch.setattr(tool_result_scanner.signal, "getitimer", lambda timer: (0.0, 0.0))
    monkeypatch.setattr(tool_result_scanner.signal, "getsignal", lambda signal_number: previous_handler)
    monkeypatch.setattr(
        tool_result_scanner.signal,
        "signal",
        lambda signal_number, handler: installed_handlers.append(handler),
    )

    def fail_setitimer(*args: object) -> None:
        del args
        raise OSError("synthetic timer failure")

    monkeypatch.setattr(tool_result_scanner.signal, "setitimer", fail_setitimer)
    report = scan_tool_result_bytes(_fixture_bytes("schema-mismatch", "near-miss"))
    assert report.verdict == "unknown"
    assert installed_handlers[-1] is previous_handler


def test_large_json_integer_does_not_overflow_numeric_shape_checks() -> None:
    payload = _fixture_payload()
    payload["calls"][0]["response"]["result"]["content"][0]["annotations"] = {
        "priority": 10**1000,
    }
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR004" in {finding.rule_id for finding in report.findings}


def test_malformed_tool_annotations_cannot_pass_list_shape_validation() -> None:
    payload = _fixture_payload()
    payload["toolsList"]["response"]["result"]["tools"][0]["annotations"] = {"readOnlyHint": "yes"}
    report = _scan_payload(payload)
    assert report.verdict == "fail"
    assert "MCPTR003" in {finding.rule_id for finding in report.findings}


def test_truncated_and_malformed_json_produce_explicit_unknown_coverage() -> None:
    for input_bytes in (b'{"schemaVersion":', b"not-json", b"\xff"):
        report = scan_tool_result_bytes(input_bytes)
        assert report.verdict == "unknown"
        assert report.coverage == "incomplete"
        assert [finding.rule_id for finding in report.findings] == ["MCPTR000"]


def test_strict_fixture_parser_rejects_unknown_envelope_fields_as_unknown() -> None:
    payload = _fixture_payload()
    payload["unexpected"] = True
    report = _scan_payload(payload)
    assert report.verdict == "unknown"
    assert report.fixture_id == "unparseable"


def test_strict_fixture_parser_rejects_duplicate_object_keys_as_unknown() -> None:
    fixture_bytes = _fixture_bytes("schema-mismatch", "negative").lstrip()
    input_bytes = b'{"schemaVersion":"mcpaudit.tool-result.fixture.v1",' + fixture_bytes[1:]
    report = scan_tool_result_bytes(input_bytes)
    assert report.verdict == "unknown"
    assert report.fixture_id == "unparseable"
    assert {finding.rule_id for finding in report.findings} == {"MCPTR000"}


def test_report_is_byte_stable_and_round_trips_its_schema() -> None:
    input_bytes = _fixture_bytes("schema-mismatch", "vulnerable")
    first = report_json_bytes(scan_tool_result_bytes(input_bytes))
    second = report_json_bytes(scan_tool_result_bytes(input_bytes))
    assert first == second
    assert first.endswith(b"\n")
    ToolResultReport.model_validate_json(first)


def test_fixture_and_report_json_schemas_are_strict() -> None:
    fixture_schema = ToolResultFixture.model_json_schema()
    report_schema = ToolResultReport.model_json_schema()
    assert fixture_schema["additionalProperties"] is False
    assert report_schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("category", "variant", "exit_code"),
    [
        ("schema-mismatch", "near-miss", 0),
        ("schema-mismatch", "vulnerable", 1),
        ("channel-divergence", "near-miss", 0),
        ("policy-contradiction", "vulnerable", 1),
        ("malformed-error", "vulnerable", 1),
        ("resource-limit", "vulnerable", 1),
        ("composition-ref", "vulnerable", 1),
    ],
)
def test_offline_cli_smokes(
    category: str,
    variant: str,
    exit_code: int,
) -> None:
    result = CliRunner().invoke(
        main,
        ["tool-result", "scan", str(FIXTURE_DIR / f"{category}-{variant}.json")],
    )
    assert result.exit_code == exit_code
    payload = json.loads(result.output)
    assert payload["schemaVersion"] == "mcpaudit.tool-result.report.v1"


def test_offline_cli_unsupported_revision_smoke() -> None:
    result = CliRunner().invoke(
        main,
        ["tool-result", "scan", str(FIXTURE_DIR / "unsupported-version.json")],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["verdict"] == "unknown"
    assert payload["coverage"] == "unsupported"


def test_cli_json_output_is_explicit_and_no_clobber(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    fixture = FIXTURE_DIR / "schema-mismatch-near-miss.json"
    runner = CliRunner()
    first = runner.invoke(main, ["tool-result", "scan", str(fixture), "--json", str(output)])
    assert first.exit_code == 0
    assert first.output == ""
    assert ToolResultReport.model_validate_json(output.read_bytes()).verdict == "pass"
    second = runner.invoke(main, ["tool-result", "scan", str(fixture), "--json", str(output)])
    assert second.exit_code == 2
    assert "output already exists" in second.output


def test_cli_schema_commands_emit_parseable_json_schema() -> None:
    runner = CliRunner()
    for contract in ("fixture", "report"):
        result = runner.invoke(main, ["tool-result", "schema", contract])
        assert result.exit_code == 0
        assert json.loads(result.output)["type"] == "object"
