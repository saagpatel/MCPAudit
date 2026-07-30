"""Fixture-first tests for the offline MCP cache contract auditor."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mcp_audit.cache_contract_models import (
    MAX_EVENTS,
    MAX_FINDINGS,
    MAX_INPUT_BYTES,
    MAX_JSON_KEY_LENGTH,
    MAX_KEY_BYTES,
    MAX_LOGICAL_MS,
    MAX_RESULT_BYTES,
    MAX_RETAINED_ENTRIES,
    CacheAuditReport,
    CacheTrace,
)
from mcp_audit.cache_contract_scanner import (
    CacheContractInputError,
    report_json_bytes,
    scan_cache_bytes,
    scan_cache_path,
)
from mcp_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "cache_contract"


def _report(name: str) -> CacheAuditReport:
    return scan_cache_path(FIXTURES / name)


@pytest.mark.parametrize(
    ("name", "verdict", "rule_ids"),
    [
        ("missing-metadata-vulnerable.json", "fail", {"MCPCACHE001"}),
        ("missing-metadata-negative.json", "pass", set()),
        ("missing-metadata-near-miss.json", "unknown", {"MCPCACHE000"}),
        ("invalid-ttl-vulnerable.json", "fail", {"MCPCACHE002"}),
        ("invalid-ttl-negative.json", "pass", set()),
        ("invalid-ttl-near-miss.json", "pass", set()),
        ("private-reuse-vulnerable.json", "fail", {"MCPCACHE003"}),
        ("private-reuse-negative.json", "pass", set()),
        ("private-reuse-near-miss.json", "pass", set()),
        ("wrong-key-vulnerable.json", "fail", {"MCPCACHE004"}),
        ("wrong-key-negative.json", "pass", set()),
        ("wrong-key-near-miss.json", "unknown", {"MCPCACHE000"}),
        ("expiry-vulnerable.json", "fail", {"MCPCACHE005"}),
        ("expiry-negative.json", "pass", set()),
        ("expiry-near-miss.json", "pass", set()),
        ("refresh-vulnerable.json", "fail", {"MCPCACHE005"}),
        ("refresh-negative.json", "pass", set()),
        ("refresh-near-miss.json", "pass", set()),
        ("change-event-vulnerable.json", "fail", {"MCPCACHE007"}),
        ("change-event-negative.json", "pass", set()),
        ("change-event-near-miss.json", "unknown", {"MCPCACHE000"}),
        ("benign-event-vulnerable.json", "fail", {"MCPCACHE007"}),
        ("benign-event-negative.json", "pass", set()),
        ("benign-event-near-miss.json", "pass", set()),
        ("ordering-drift-vulnerable.json", "fail", {"MCPCACHE006"}),
        ("ordering-drift-negative.json", "pass", set()),
        ("ordering-drift-near-miss.json", "pass", set()),
        ("clock-ambiguity-vulnerable.json", "unknown", {"MCPCACHE000"}),
        ("clock-ambiguity-negative.json", "pass", set()),
        ("clock-ambiguity-near-miss.json", "pass", set()),
        ("truncated-trace-vulnerable.json", "unknown", {"MCPCACHE000"}),
        ("truncated-trace-negative.json", "pass", set()),
        ("truncated-trace-near-miss.json", "fail", {"MCPCACHE000", "MCPCACHE003"}),
    ],
)
def test_semantic_fixture_triplets(
    name: str,
    verdict: str,
    rule_ids: set[str],
) -> None:
    report = _report(name)
    assert report.verdict == verdict
    assert {finding.rule_id for finding in report.findings} == rule_ids
    assert report.coverage.state == ("complete" if "MCPCACHE000" not in rule_ids else "incomplete")


@pytest.mark.parametrize("next_cursor", [None, 7, {"opaque": "cursor"}])
def test_malformed_next_cursor_is_explicit_unknown(next_cursor: object) -> None:
    payload = json.loads((FIXTURES / "ordering-drift-vulnerable.json").read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["result"]["nextCursor"] = next_cursor

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"pagination_cursor_shape_unverified"}
    assert report.coverage.state == "incomplete"


def test_malformed_request_cursor_is_explicit_unknown() -> None:
    payload = json.loads((FIXTURES / "ordering-drift-vulnerable.json").read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["request"]["params"]["cursor"] = None

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.evidence for finding in report.findings} == {"pagination_cursor_shape_unverified"}


@pytest.mark.parametrize("event_type", ["use", "refresh_error"])
def test_malformed_use_like_cursor_is_not_further_graded(event_type: str) -> None:
    payload = json.loads((FIXTURES / "expiry-negative.json").read_text(encoding="utf-8"))
    payload["events"][1]["type"] = event_type
    payload["events"][1]["request"]["params"]["cursor"] = None

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"pagination_cursor_shape_unverified"}


def test_malformed_cursor_does_not_poison_supported_partition_evidence() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"].insert(
        0,
        {
            "type": "use",
            "event_id": "malformed-use",
            "sequence": 1,
            "at_ms": 0,
            "source_event_id": "not-observed",
            "request": {
                "protocol_version": "2026-07-28",
                "principal": "bob",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {"cursor": None},
            },
        },
    )
    payload["events"][1]["sequence"] = 2
    payload["events"][2]["sequence"] = 3

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "pagination_cursor_shape_unverified",
        "use_at_or_after_ttl_boundary",
    }


def test_empty_string_next_cursor_remains_valid_paginated_evidence() -> None:
    payload = json.loads((FIXTURES / "ordering-drift-vulnerable.json").read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["result"]["nextCursor"] = ""

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "pass"
    assert report.coverage.state == "complete"


@pytest.mark.parametrize(
    "fixture_name",
    ["ordering-drift-near-miss.json", "ordering-drift-vulnerable.json"],
)
def test_private_ordering_principal_conflict_is_unknown(fixture_name: str) -> None:
    payload = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["result"]["cacheScope"] = "private"
    payload["events"][1]["request"]["principal"] = "bob"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"authorization_partition_mapping_ambiguous"}


def test_public_ordering_check_survives_partition_principal_conflict() -> None:
    payload = json.loads((FIXTURES / "ordering-drift-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][1]["request"]["principal"] = "bob"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000", "MCPCACHE006"}


def test_private_ordering_survives_uncomputable_expiry_with_known_partition() -> None:
    payload = json.loads((FIXTURES / "ordering-drift-vulnerable.json").read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["result"]["cacheScope"] = "private"
    payload["events"][1]["at_ms"] = MAX_LOGICAL_MS
    payload["events"][1]["result"]["ttlMs"] = 1

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "expiry_outside_simulator_clock",
        "tools_list_order_drift",
    }


def test_private_partition_mapping_conflict_remains_ambiguous() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    conflict = json.loads(json.dumps(payload["events"][0]))
    conflict["event_id"] = "r2"
    conflict["sequence"] = 2
    conflict["at_ms"] = 5
    conflict["request"]["principal"] = "bob"
    payload["events"][1]["sequence"] = 3
    payload["events"][2]["sequence"] = 4
    payload["events"].insert(1, conflict)

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"authorization_partition_mapping_ambiguous"}


def test_malformed_fixture_is_explicit_unknown() -> None:
    report = _report("malformed.json")
    assert report.verdict == "unknown"
    assert report.coverage.input_state == "malformed"
    assert [finding.rule_id for finding in report.findings] == ["MCPCACHE000"]


@pytest.mark.parametrize(
    ("original", "duplicate"),
    [
        (b'"ttlMs":100', b'"ttlMs":-1,"ttlMs":100'),
        (b'"method":"tools/list"', b'"method":"resources/list","method":"tools/list"'),
    ],
)
def test_duplicate_json_members_are_explicit_unknown(original: bytes, duplicate: bytes) -> None:
    raw = (FIXTURES / "missing-metadata-negative.json").read_bytes()
    assert original in raw
    report = scan_cache_bytes(raw.replace(original, duplicate, 1))
    assert report.verdict == "unknown"
    assert report.coverage.input_state == "malformed"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}


def test_unsupported_version_is_not_graded_green() -> None:
    report = _report("unsupported.json")
    assert report.verdict == "unknown"
    assert report.coverage.input_state == "unsupported"
    assert report.protocol_versions == ["2025-11-25"]


def test_unsupported_trace_version_stops_current_event_grading() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["protocol_version"] = "2025-11-25"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert report.coverage.input_state == "unsupported"
    assert report.coverage.analyzed_events == 2
    assert report.coverage.retained_entries == 0
    assert report.protocol_versions == ["2025-11-25", "2026-07-28"]
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_protocol_version"}


@pytest.mark.parametrize("event_type", ["use", "refresh_error"])
def test_unsupported_use_like_event_is_not_further_graded(event_type: str) -> None:
    payload = json.loads((FIXTURES / "expiry-negative.json").read_text(encoding="utf-8"))
    payload["events"][1]["type"] = event_type
    payload["events"][1]["request"]["protocol_version"] = "2025-11-25"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_event_protocol_version"}


def test_unsupported_event_does_not_poison_supported_partition_evidence() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"].insert(
        0,
        {
            "type": "use",
            "event_id": "unsupported-use",
            "sequence": 1,
            "at_ms": 0,
            "source_event_id": "not-observed",
            "request": {
                "protocol_version": "2025-11-25",
                "principal": "bob",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {},
            },
        },
    )
    payload["events"][1]["sequence"] = 2
    payload["events"][2]["sequence"] = 3

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "unsupported_event_protocol_version",
        "use_at_or_after_ttl_boundary",
    }


@pytest.mark.parametrize("event_type", ["use", "refresh_error"])
def test_source_unverified_event_does_not_poison_supported_partition_evidence(
    event_type: str,
) -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"].insert(
        0,
        {
            "type": event_type,
            "event_id": "orphan-event",
            "sequence": 1,
            "at_ms": 0,
            "source_event_id": "not-observed",
            "request": {
                "protocol_version": "2026-07-28",
                "principal": "bob",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {},
            },
        },
    )
    payload["events"][1]["sequence"] = 2
    payload["events"][2]["sequence"] = 3

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "cache_source_unverified",
        "use_at_or_after_ttl_boundary",
    }


def test_partially_gradable_source_does_not_poison_supported_partition_evidence() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    partial_request = {
        "protocol_version": "2026-07-28",
        "principal": "alice",
        "cache_partition": "auth-a",
        "method": "tools/list",
        "params": {},
    }
    payload["events"][0]["sequence"] = 3
    payload["events"][1]["sequence"] = 4
    payload["events"][0:0] = [
        {
            "type": "response",
            "event_id": "partial-source",
            "sequence": 1,
            "at_ms": 0,
            "request": partial_request,
            "result": {
                "resultType": "complete",
                "ttlMs": MAX_LOGICAL_MS + 1,
                "cacheScope": "private",
                "tools": [],
            },
        },
        {
            "type": "use",
            "event_id": "partial-use",
            "sequence": 2,
            "at_ms": 0,
            "source_event_id": "partial-source",
            "request": {
                **partial_request,
                "principal": "bob",
            },
        },
    ]

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "ttl_outside_simulator_clock",
        "use_at_or_after_ttl_boundary",
    }


def test_source_without_computable_expiry_does_not_poison_partition_evidence() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    partial_request = {
        "protocol_version": "2026-07-28",
        "principal": "alice",
        "cache_partition": "auth-a",
        "method": "tools/list",
        "params": {},
    }
    payload["events"][0]["sequence"] = 3
    payload["events"][0]["at_ms"] = MAX_LOGICAL_MS
    payload["events"][0]["result"]["ttlMs"] = 0
    payload["events"][1]["sequence"] = 4
    payload["events"][1]["at_ms"] = MAX_LOGICAL_MS
    payload["events"][0:0] = [
        {
            "type": "response",
            "event_id": "overflow-source",
            "sequence": 1,
            "at_ms": MAX_LOGICAL_MS,
            "request": partial_request,
            "result": {
                "resultType": "complete",
                "ttlMs": 1,
                "cacheScope": "private",
                "tools": [],
            },
        },
        {
            "type": "use",
            "event_id": "overflow-use",
            "sequence": 2,
            "at_ms": MAX_LOGICAL_MS,
            "source_event_id": "overflow-source",
            "request": {
                **partial_request,
                "principal": "bob",
            },
        },
    ]

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "expiry_outside_simulator_clock",
        "use_at_or_after_ttl_boundary",
    }


@pytest.mark.parametrize(
    ("mutation", "evidence"),
    [
        ("request-key", "cache_request_key_mismatch"),
        ("private-partition", "private_cross_partition_reuse"),
    ],
)
def test_uncomputable_expiry_preserves_expiry_independent_violations(
    mutation: str,
    evidence: str,
) -> None:
    payload = json.loads((FIXTURES / "expiry-negative.json").read_text(encoding="utf-8"))
    response, use = payload["events"]
    response["at_ms"] = MAX_LOGICAL_MS
    response["result"]["ttlMs"] = 1
    use["at_ms"] = MAX_LOGICAL_MS
    if mutation == "request-key":
        use["request"]["params"] = {"filter": "different"}
    else:
        use["request"]["principal"] = "bob"
        use["request"]["cache_partition"] = "auth-b"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        evidence,
        "expiry_outside_simulator_clock",
    }


def test_uncomputable_expiry_does_not_establish_notification_freshness() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    for event in payload["events"]:
        event["at_ms"] = MAX_LOGICAL_MS
    payload["events"][0]["result"]["ttlMs"] = 1

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"expiry_outside_simulator_clock"}


@pytest.mark.parametrize("event_type", ["use", "refresh_error"])
def test_unsupported_use_like_method_is_not_further_graded(event_type: str) -> None:
    payload = json.loads((FIXTURES / "expiry-negative.json").read_text(encoding="utf-8"))
    payload["events"][1]["type"] = event_type
    payload["events"][1]["request"]["method"] = "server/discover"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_cacheable_method"}


def test_event_serialization_order_does_not_change_output() -> None:
    payload = json.loads((FIXTURES / "change-event-negative.json").read_text(encoding="utf-8"))
    original = report_json_bytes(scan_cache_bytes(json.dumps(payload).encode()))
    payload["events"].reverse()
    reordered = report_json_bytes(scan_cache_bytes(json.dumps(payload).encode()))
    assert reordered == original


def test_wall_clock_is_not_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = (FIXTURES / "refresh-negative.json").read_bytes()
    first = report_json_bytes(scan_cache_bytes(raw))
    monkeypatch.setattr(time, "time", lambda: 9_999_999_999.0)
    second = report_json_bytes(scan_cache_bytes(raw))
    assert second == first


def test_report_is_canonical_and_does_not_reflect_private_trace_values() -> None:
    report_bytes = report_json_bytes(_report("wrong-key-vulnerable.json"))
    assert report_bytes.endswith(b"\n")
    assert not report_bytes.endswith(b"\n\n")
    assert b"alice" not in report_bytes
    assert b"bob" not in report_bytes
    assert b"test://alpha" not in report_bytes
    assert b"test://beta" not in report_bytes
    assert json.dumps(json.loads(report_bytes), sort_keys=True, separators=(",", ":")).encode() + b"\n" == (
        report_bytes
    )


def test_private_partition_mapping_conflict_is_unknown() -> None:
    payload = json.loads((FIXTURES / "private-reuse-negative.json").read_text(encoding="utf-8"))
    payload["events"][2]["request"]["principal"] = "bob"
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}


def _page_scope_payload() -> dict[str, Any]:
    request = {
        "protocol_version": "2026-07-28",
        "principal": "alice",
        "cache_partition": "auth-a",
        "method": "prompts/list",
        "params": {},
    }
    return {
        "schema_version": "mcpaudit.cache-contract.trace.v1",
        "trace_id": "page-scope",
        "protocol_version": "2026-07-28",
        "trace_complete": True,
        "events": [
            {
                "type": "response",
                "event_id": "p1",
                "sequence": 1,
                "at_ms": 0,
                "request": request,
                "page_group": "pages-a",
                "result": {
                    "resultType": "complete",
                    "ttlMs": 10,
                    "cacheScope": "public",
                    "prompts": [],
                    "nextCursor": "next",
                },
            },
            {
                "type": "response",
                "event_id": "p2",
                "sequence": 2,
                "at_ms": 1,
                "request": {**request, "params": {"cursor": "next"}},
                "page_group": "pages-a",
                "result": {
                    "resultType": "complete",
                    "ttlMs": 20,
                    "cacheScope": "private",
                    "prompts": [],
                },
            },
        ],
    }


def test_paginated_pages_must_keep_one_cache_scope() -> None:
    payload = _page_scope_payload()
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE008"}


@pytest.mark.parametrize("malformed_field", ["cursor", "nextCursor"])
def test_malformed_cursor_skips_linked_page_scope_grading(malformed_field: str) -> None:
    payload = _page_scope_payload()
    if malformed_field == "cursor":
        payload["events"][1]["request"]["params"]["cursor"] = None
    else:
        payload["events"][0]["result"]["nextCursor"] = None

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"pagination_cursor_shape_unverified"}


@pytest.mark.parametrize("identity_drift", ["partition", "params"])
def test_paginated_page_chain_identity_drift_is_unknown(identity_drift: str) -> None:
    request = {
        "protocol_version": "2026-07-28",
        "principal": "alice",
        "cache_partition": "auth-a",
        "method": "prompts/list",
        "params": {},
    }
    next_request = {**request, "params": {"cursor": "next"}}
    if identity_drift == "partition":
        next_request["principal"] = "bob"
        next_request["cache_partition"] = "auth-b"
    else:
        next_request["params"] = {"cursor": "next", "filter": "different"}
    payload = {
        "schema_version": "mcpaudit.cache-contract.trace.v1",
        "trace_id": "page-chain-identity",
        "protocol_version": "2026-07-28",
        "trace_complete": True,
        "events": [
            {
                "type": "response",
                "event_id": "p1",
                "sequence": 1,
                "at_ms": 0,
                "request": request,
                "page_group": "pages-a",
                "result": {
                    "resultType": "complete",
                    "ttlMs": 10,
                    "cacheScope": "public",
                    "prompts": [],
                    "nextCursor": "next",
                },
            },
            {
                "type": "response",
                "event_id": "p2",
                "sequence": 2,
                "at_ms": 1,
                "request": next_request,
                "page_group": "pages-a",
                "result": {
                    "resultType": "complete",
                    "ttlMs": 20,
                    "cacheScope": "public",
                    "prompts": [],
                },
            },
        ],
    }
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert report.findings[0].evidence == "page_chain_request_identity_ambiguous"


@pytest.mark.parametrize(
    "params",
    [{"requestState": "synthetic"}, {"inputResponses": {"answer": {"action": "accept"}}}],
)
def test_multi_round_trip_retry_result_is_not_cacheable(params: dict[str, object]) -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["request"]["params"] = params
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert "MCPCACHE009" in {finding.rule_id for finding in report.findings}


def test_input_required_result_is_not_cacheable() -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"] = {"resultType": "input_required", "inputRequests": {}}
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE009"}


def test_input_required_violation_survives_malformed_cursor() -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["request"]["params"]["cursor"] = None
    payload["events"][0]["result"] = {"resultType": "input_required", "inputRequests": {}}

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000", "MCPCACHE009"}
    assert {finding.evidence for finding in report.findings} == {
        "input_required_result_cached",
        "pagination_cursor_shape_unverified",
    }


@pytest.mark.parametrize("result_type", [None, {}, []])
def test_malformed_result_type_is_structured_unknown(
    result_type: object,
    tmp_path: Path,
) -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["resultType"] = result_type

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_result_type"}

    trace_path = tmp_path / "malformed-result-type.json"
    trace_path.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(main, ["cache-contract", "scan", str(trace_path)])
    assert result.exit_code == 1, result.output
    cli_report = json.loads(result.output)
    assert cli_report["verdict"] == "unknown"
    assert {finding["evidence"] for finding in cli_report["findings"]} == {"unsupported_result_type"}


@pytest.mark.parametrize(
    ("fixture_name", "event_index", "payload_field"),
    [
        ("expiry-vulnerable.json", 0, "tools"),
        ("change-event-vulnerable.json", 0, "tools"),
        ("wrong-key-vulnerable.json", 0, "contents"),
        ("refresh-negative.json", 1, "tools"),
    ],
)
def test_malformed_payload_is_not_further_graded(
    fixture_name: str,
    event_index: int,
    payload_field: str,
) -> None:
    payload = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    payload["events"][event_index]["result"][payload_field] = {}

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"cacheable_payload_unverified"}


@pytest.mark.parametrize(
    ("method", "payload_field", "member"),
    [
        ("tools/list", "tools", None),
        ("tools/list", "tools", {}),
        ("prompts/list", "prompts", None),
        ("resources/list", "resources", None),
        ("resources/templates/list", "resourceTemplates", None),
        ("resources/read", "contents", None),
    ],
)
def test_malformed_payload_member_is_not_further_graded(
    method: str,
    payload_field: str,
    member: object,
) -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    event = payload["events"][0]
    event["request"]["method"] = method
    if method == "resources/read":
        event["request"]["params"] = {"uri": "test://resource"}
    event["result"] = {
        "resultType": "complete",
        "ttlMs": 100,
        "cacheScope": "private",
        payload_field: [member],
    }

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"cacheable_payload_unverified"}


@pytest.mark.parametrize(
    ("bad_result", "bad_evidence"),
    [
        (
            {
                "resultType": "streaming",
                "ttlMs": 100,
                "cacheScope": "private",
                "tools": [],
            },
            "unsupported_result_type",
        ),
        (
            {
                "resultType": "complete",
                "ttlMs": 100,
                "cacheScope": "private",
                "tools": [None],
            },
            "cacheable_payload_unverified",
        ),
        (
            {
                "ttlMs": 100,
                "cacheScope": "private",
                "tools": [],
            },
            "required_result_type_missing",
        ),
    ],
)
def test_ungradable_response_does_not_poison_supported_partition_evidence(
    bad_result: dict[str, object],
    bad_evidence: str,
) -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"].insert(
        0,
        {
            "type": "response",
            "event_id": "ungradable-response",
            "sequence": 1,
            "at_ms": 0,
            "request": {
                "protocol_version": "2026-07-28",
                "principal": "bob",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {},
            },
            "result": bad_result,
        },
    )
    payload["events"][1]["sequence"] = 2
    payload["events"][2]["sequence"] = 3

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        bad_evidence,
        "use_at_or_after_ttl_boundary",
    }


def test_response_without_computable_expiry_does_not_poison_partition_evidence() -> None:
    payload = json.loads((FIXTURES / "expiry-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][0]["sequence"] = 2
    payload["events"][0]["at_ms"] = MAX_LOGICAL_MS
    payload["events"][0]["result"]["ttlMs"] = 0
    payload["events"][1]["sequence"] = 3
    payload["events"][1]["at_ms"] = MAX_LOGICAL_MS
    payload["events"].insert(
        0,
        {
            "type": "response",
            "event_id": "overflow-response",
            "sequence": 1,
            "at_ms": MAX_LOGICAL_MS,
            "request": {
                "protocol_version": "2026-07-28",
                "principal": "bob",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {},
            },
            "result": {
                "resultType": "complete",
                "ttlMs": 1,
                "cacheScope": "private",
                "tools": [],
            },
        },
    )

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.evidence for finding in report.findings} == {
        "expiry_outside_simulator_clock",
        "use_at_or_after_ttl_boundary",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ttlMs", True),
        ("ttlMs", "100"),
        ("cacheScope", "shared"),
        ("cacheScope", 1),
        ("cacheScope", {}),
        ("cacheScope", []),
    ],
)
def test_invalid_cache_metadata_types_are_rejected(
    field: str,
    value: object,
    tmp_path: Path,
) -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"][field] = value
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE002"}

    trace_path = tmp_path / "invalid-metadata.json"
    trace_path.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(main, ["cache-contract", "scan", str(trace_path)])
    assert result.exit_code == 1, result.output
    cli_report = json.loads(result.output)
    assert cli_report["verdict"] == "fail"
    assert {finding["rule_id"] for finding in cli_report["findings"]} == {"MCPCACHE002"}


def test_public_cache_key_still_binds_method() -> None:
    payload = json.loads((FIXTURES / "wrong-key-negative.json").read_text(encoding="utf-8"))
    payload["events"][1]["request"]["method"] = "tools/list"
    payload["events"][1]["request"]["params"] = {}
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE004"}


def test_mismatched_refresh_error_does_not_authorize_stale_use() -> None:
    payload = json.loads((FIXTURES / "expiry-near-miss.json").read_text(encoding="utf-8"))
    payload["events"][1]["request"]["params"] = {"cursor": "wrong-key"}
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {
        "MCPCACHE004",
        "MCPCACHE005",
    }


def test_refresh_error_before_expiry_does_not_authorize_later_stale_use() -> None:
    payload = json.loads((FIXTURES / "expiry-near-miss.json").read_text(encoding="utf-8"))
    payload["events"][1]["at_ms"] = 50
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE005"}


def test_successful_refresh_supersedes_prior_ttl_refresh_error() -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    refresh = payload["events"][1]
    refresh["sequence"] = 3
    refresh["at_ms"] = 11
    refresh["source_event_id"] = "r1"
    payload["events"].insert(
        1,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 2,
            "at_ms": 10,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
        },
    )
    payload["events"][3]["sequence"] = 4
    payload["events"][3]["source_event_id"] = "r1"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE005"}


@pytest.mark.parametrize(
    ("refresh_scope", "expected_verdict", "expected_rule_ids"),
    [
        ("public", "fail", {"MCPCACHE000", "MCPCACHE005"}),
        ("private", "unknown", {"MCPCACHE000"}),
    ],
)
def test_public_refresh_scope_respects_partition_principal_conflict(
    refresh_scope: str,
    expected_verdict: str,
    expected_rule_ids: set[str],
) -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["cacheScope"] = "public"
    refresh = payload["events"][1]
    refresh["sequence"] = 4
    refresh["at_ms"] = 11
    refresh["source_event_id"] = "r1"
    refresh["result"]["cacheScope"] = refresh_scope
    conflict = json.loads(json.dumps(payload["events"][0]))
    conflict["event_id"] = "r-conflict"
    conflict["sequence"] = 3
    conflict["at_ms"] = 10
    conflict["request"]["principal"] = "bob"
    payload["events"].insert(
        1,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 2,
            "at_ms": 10,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
        },
    )
    payload["events"].insert(2, conflict)
    payload["events"][4]["sequence"] = 5
    payload["events"][4]["source_event_id"] = "r1"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == expected_verdict
    assert {finding.rule_id for finding in report.findings} == expected_rule_ids


def test_malformed_refresh_cursor_does_not_supersede_prior_refresh_error() -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    refresh = payload["events"][1]
    refresh["sequence"] = 3
    refresh["at_ms"] = 11
    refresh["source_event_id"] = "r1"
    refresh["result"]["nextCursor"] = None
    payload["events"].insert(
        1,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 2,
            "at_ms": 10,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
        },
    )
    payload["events"][3]["sequence"] = 4
    payload["events"][3]["source_event_id"] = "r1"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"pagination_cursor_shape_unverified"}


def test_successful_refresh_supersedes_prior_notification_refresh_error() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    request = payload["events"][0]["request"]
    refresh_result = payload["events"][0]["result"]
    payload["events"][2]["sequence"] = 5
    payload["events"].insert(
        2,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 3,
            "at_ms": 11,
            "source_event_id": "r1",
            "request": request,
        },
    )
    payload["events"].insert(
        3,
        {
            "type": "refresh",
            "event_id": "r2",
            "sequence": 4,
            "at_ms": 12,
            "source_event_id": "r1",
            "request": request,
            "result": refresh_result,
        },
    )

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE007"}


@pytest.mark.parametrize("event_type", ["refresh", "refresh_error"])
def test_private_refresh_source_cannot_cross_partition(event_type: str) -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    payload["events"] = payload["events"][:2]
    refresh = payload["events"][1]
    refresh["request"]["principal"] = "bob"
    refresh["request"]["cache_partition"] = "auth-b"
    if event_type == "refresh_error":
        refresh["type"] = "refresh_error"
        del refresh["result"]
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE003"}


@pytest.mark.parametrize("event_type", ["refresh", "refresh_error"])
def test_private_refresh_principal_conflict_is_unknown(event_type: str) -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    payload["events"] = payload["events"][:2]
    refresh = payload["events"][1]
    refresh["request"]["principal"] = "bob"
    if event_type == "refresh_error":
        refresh["type"] = "refresh_error"
        del refresh["result"]
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert report.findings[0].evidence == "authorization_partition_mapping_ambiguous"


def test_only_refresh_error_after_notification_authorizes_stale_use() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    error = {
        "type": "refresh_error",
        "event_id": "x1",
        "sequence": 2,
        "at_ms": 5,
        "source_event_id": "r1",
        "request": payload["events"][0]["request"],
    }
    payload["events"][1]["sequence"] = 3
    payload["events"][2]["sequence"] = 4
    payload["events"].insert(1, error)
    before_notification = scan_cache_bytes(json.dumps(payload).encode())
    assert {finding.rule_id for finding in before_notification.findings} == {"MCPCACHE007"}

    payload["events"][1]["sequence"] = 3
    payload["events"][1]["at_ms"] = 11
    payload["events"][2]["sequence"] = 2
    after_notification = scan_cache_bytes(json.dumps(payload).encode())
    assert after_notification.verdict == "pass"


def test_notification_refresh_error_authorizes_use_after_later_ttl_boundary() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][2]["sequence"] = 4
    payload["events"][2]["at_ms"] = 101
    payload["events"].insert(
        2,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 3,
            "at_ms": 20,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
        },
    )

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "pass"
    assert report.coverage.state == "complete"


def test_successful_refresh_supersedes_invalidation_before_later_refresh_error() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][2]["sequence"] = 5
    payload["events"][2]["at_ms"] = 101
    payload["events"].insert(
        2,
        {
            "type": "refresh",
            "event_id": "r2",
            "sequence": 3,
            "at_ms": 20,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
            "result": payload["events"][0]["result"],
        },
    )
    payload["events"].insert(
        3,
        {
            "type": "refresh_error",
            "event_id": "x1",
            "sequence": 4,
            "at_ms": 30,
            "source_event_id": "r1",
            "request": payload["events"][0]["request"],
        },
    )

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE005", "MCPCACHE007"}


def test_public_entry_notification_invalidation_applies_to_every_later_use() -> None:
    payload = json.loads((FIXTURES / "private-reuse-near-miss.json").read_text(encoding="utf-8"))
    payload["events"][1]["sequence"] = 3
    payload["events"].insert(
        1,
        {
            "type": "notification",
            "event_id": "n1",
            "sequence": 2,
            "at_ms": 5,
            "principal": "alice",
            "cache_partition": "auth-a",
            "method": "notifications/tools/list_changed",
            "params": {},
            "subscription_validated": True,
        },
    )
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE007"}


def test_public_notification_check_survives_partition_principal_conflict() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["cacheScope"] = "public"
    conflict = json.loads(json.dumps(payload["events"][0]))
    conflict["event_id"] = "r2"
    conflict["sequence"] = 2
    conflict["at_ms"] = 5
    conflict["request"]["principal"] = "bob"
    payload["events"][1]["sequence"] = 3
    payload["events"][2]["sequence"] = 4
    payload["events"].insert(1, conflict)

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "fail"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000", "MCPCACHE007"}


def test_notification_does_not_invalidate_an_entry_with_unknown_scope() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["resultType"] = "unsupported"

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_result_type"}


@pytest.mark.parametrize("event_type", ["use", "refresh_error"])
def test_use_like_event_does_not_grade_an_entry_with_unknown_scope(event_type: str) -> None:
    payload = json.loads((FIXTURES / "wrong-key-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["resultType"] = "unsupported"
    payload["events"][1]["type"] = event_type

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_result_type"}


def test_refresh_does_not_grade_a_source_with_unknown_scope() -> None:
    payload = json.loads((FIXTURES / "refresh-negative.json").read_text(encoding="utf-8"))
    payload["events"] = payload["events"][:2]
    payload["events"][0]["result"]["resultType"] = "unsupported"
    payload["events"][1]["request"]["params"] = {"cursor": "different-key"}

    report = scan_cache_bytes(json.dumps(payload).encode())

    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert {finding.evidence for finding in report.findings} == {"unsupported_result_type"}


def test_public_entry_refresh_error_applies_to_shared_entry() -> None:
    payload = json.loads((FIXTURES / "expiry-near-miss.json").read_text(encoding="utf-8"))
    payload["events"][0]["result"]["cacheScope"] = "public"
    payload["events"][2]["request"]["principal"] = "bob"
    payload["events"][2]["request"]["cache_partition"] = "auth-b"
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "pass"


def test_private_notification_principal_conflict_is_unknown() -> None:
    payload = json.loads((FIXTURES / "change-event-vulnerable.json").read_text(encoding="utf-8"))
    payload["events"][1]["principal"] = "bob"
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert report.findings[0].evidence == "authorization_partition_mapping_ambiguous"


def test_resource_notification_without_uri_is_unknown_without_cached_entries() -> None:
    payload = {
        "schema_version": "mcpaudit.cache-contract.trace.v1",
        "trace_id": "resource-notification-missing-uri",
        "protocol_version": "2026-07-28",
        "trace_complete": True,
        "events": [
            {
                "type": "notification",
                "event_id": "n1",
                "sequence": 1,
                "at_ms": 0,
                "principal": "alice",
                "cache_partition": "auth-a",
                "method": "notifications/resources/updated",
                "params": {},
                "subscription_validated": True,
            }
        ],
    }
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert report.findings[0].evidence == "resource_notification_uri_unverified"


@pytest.mark.parametrize("malformed_event", ["response", "use"])
def test_resource_read_without_uri_is_unknown(malformed_event: str) -> None:
    payload = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    response = payload["events"][0]
    response["request"]["method"] = "resources/read"
    response["request"]["params"] = {"uri": "test://resource"}
    response["result"]["contents"] = []
    del response["result"]["tools"]
    if malformed_event == "response":
        response["request"]["params"] = {}
    else:
        payload["events"].append(
            {
                "type": "use",
                "event_id": "u1",
                "sequence": 2,
                "at_ms": 1,
                "source_event_id": response["event_id"],
                "request": {
                    **response["request"],
                    "params": {},
                },
            }
        )
    report = scan_cache_bytes(json.dumps(payload).encode())
    assert report.verdict == "unknown"
    assert {finding.rule_id for finding in report.findings} == {"MCPCACHE000"}
    assert report.findings[0].evidence == "resource_request_uri_unverified"


def test_input_and_state_bounds_fail_closed() -> None:
    base = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))

    oversized_result = json.loads(json.dumps(base))
    oversized_result["events"][0]["result"]["tools"] = [{"description": "x" * (MAX_RESULT_BYTES + 1)}]
    assert scan_cache_bytes(json.dumps(oversized_result).encode()).verdict == "unknown"

    oversized_key = json.loads(json.dumps(base))
    oversized_key["events"][0]["request"]["params"] = {"value": "x" * MAX_KEY_BYTES}
    assert scan_cache_bytes(json.dumps(oversized_key).encode()).verdict == "unknown"

    oversized_name = json.loads(json.dumps(base))
    oversized_name["events"][0]["request"]["params"] = {"x" * (MAX_JSON_KEY_LENGTH + 1): True}
    assert scan_cache_bytes(json.dumps(oversized_name).encode()).verdict == "unknown"

    excessive_depth = json.loads(json.dumps(base))
    nested: dict[str, object] = {}
    cursor = nested
    for _ in range(40):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    excessive_depth["events"][0]["request"]["params"] = nested
    assert scan_cache_bytes(json.dumps(excessive_depth).encode()).verdict == "unknown"

    out_of_range_clock = json.loads(json.dumps(base))
    out_of_range_clock["events"][0]["at_ms"] = MAX_LOGICAL_MS + 1
    assert scan_cache_bytes(json.dumps(out_of_range_clock).encode()).verdict == "unknown"

    assert scan_cache_bytes(b" " * (MAX_INPUT_BYTES + 1)).verdict == "unknown"


def test_finding_limit_preserves_a_late_concrete_violation() -> None:
    events = [
        {
            "type": "notification",
            "event_id": f"n{sequence}",
            "sequence": sequence,
            "at_ms": sequence,
            "principal": "alice",
            "cache_partition": "auth-a",
            "method": "notifications/unsupported",
            "params": {},
            "subscription_validated": True,
        }
        for sequence in range(1, MAX_FINDINGS)
    ]
    events.append(
        {
            "type": "response",
            "event_id": "r-invalid",
            "sequence": MAX_FINDINGS,
            "at_ms": MAX_FINDINGS,
            "request": {
                "protocol_version": "2026-07-28",
                "principal": "alice",
                "cache_partition": "auth-a",
                "method": "tools/list",
                "params": {},
            },
            "result": {
                "resultType": "complete",
                "ttlMs": -1,
                "cacheScope": "private",
                "tools": [],
            },
        }
    )
    raw = json.dumps(
        {
            "schema_version": "mcpaudit.cache-contract.trace.v1",
            "trace_id": "late-concrete-finding",
            "protocol_version": "2026-07-28",
            "trace_complete": True,
            "events": events,
        }
    ).encode()
    assert len(raw) <= MAX_INPUT_BYTES

    report = scan_cache_bytes(raw)

    assert report.verdict == "fail"
    assert len(report.findings) == MAX_FINDINGS
    assert "MCPCACHE002" in {finding.rule_id for finding in report.findings}
    assert "finding_limit_exceeded" in {finding.evidence for finding in report.findings}


def test_oversized_path_and_cli_emit_structured_unknown(tmp_path: Path) -> None:
    trace_path = tmp_path / "oversized.json"
    raw = b" " * (MAX_INPUT_BYTES + 1)
    trace_path.write_bytes(raw)

    report = scan_cache_path(trace_path)
    assert report.verdict == "unknown"
    assert report.findings[0].evidence == "input_size_limit_exceeded"
    assert report_json_bytes(report) == report_json_bytes(scan_cache_bytes(raw))

    result = CliRunner().invoke(main, ["cache-contract", "scan", str(trace_path)])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verdict"] == "unknown"
    assert payload["findings"][0]["evidence"] == "input_size_limit_exceeded"


def test_raced_fifo_is_opened_nonblocking_before_descriptor_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonblocking_flag = getattr(os, "O_NONBLOCK", 0)
    if nonblocking_flag == 0:
        pytest.skip("platform does not expose O_NONBLOCK")

    trace_path = tmp_path / "trace.json"
    trace_path.write_bytes((FIXTURES / "missing-metadata-negative.json").read_bytes())
    real_open = os.open

    def raced_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int) -> int:
        assert flags & nonblocking_flag
        trace_path.unlink()
        os.mkfifo(trace_path)
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", raced_open)

    with pytest.raises(CacheContractInputError, match="not a regular file"):
        scan_cache_path(trace_path)


def test_event_and_retained_entry_counts_are_bounded() -> None:
    base = json.loads((FIXTURES / "missing-metadata-negative.json").read_text(encoding="utf-8"))
    template = base["events"][0]
    base["events"] = []
    for index in range(MAX_RETAINED_ENTRIES + 1):
        event = json.loads(json.dumps(template))
        event["event_id"] = f"r{index}"
        event["sequence"] = index
        event["at_ms"] = index
        base["events"].append(event)
    retained_report = scan_cache_bytes(json.dumps(base).encode())
    assert retained_report.verdict == "unknown"
    assert retained_report.coverage.retained_entries == MAX_RETAINED_ENTRIES
    assert {finding.rule_id for finding in retained_report.findings} == {"MCPCACHE000"}

    base["events"] = [
        {
            "type": "notification",
            "event_id": f"n{index}",
            "sequence": index,
            "at_ms": index,
            "principal": "alice",
            "cache_partition": "auth-a",
            "method": "notifications/tools/list_changed",
            "params": {},
            "subscription_validated": True,
        }
        for index in range(MAX_EVENTS + 1)
    ]
    event_report = scan_cache_bytes(json.dumps(base).encode())
    assert event_report.verdict == "unknown"
    assert event_report.coverage.input_state == "malformed"


def test_strict_schemas_are_versioned_and_closed() -> None:
    trace_schema = CacheTrace.model_json_schema()
    report_schema = CacheAuditReport.model_json_schema()
    assert trace_schema["properties"]["schema_version"]["const"] == ("mcpaudit.cache-contract.trace.v1")
    assert trace_schema["additionalProperties"] is False
    assert report_schema["properties"]["schema_version"]["const"] == ("mcpaudit.cache-contract.report.v1")
    assert report_schema["additionalProperties"] is False


@pytest.mark.parametrize(
    ("name", "exit_code"),
    [
        ("missing-metadata-negative.json", 0),
        ("missing-metadata-vulnerable.json", 1),
        ("private-reuse-vulnerable.json", 1),
        ("wrong-key-vulnerable.json", 1),
        ("expiry-vulnerable.json", 1),
        ("refresh-negative.json", 0),
        ("malformed.json", 1),
        ("unsupported.json", 1),
        ("clock-ambiguity-vulnerable.json", 1),
    ],
)
def test_offline_cli_smokes(name: str, exit_code: int) -> None:
    result = CliRunner().invoke(main, ["cache-contract", "scan", str(FIXTURES / name)])
    assert result.exit_code == exit_code, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "mcpaudit.cache-contract.report.v1"


@pytest.mark.parametrize("contract", ["trace", "report"])
def test_cli_emits_contract_schema(contract: str) -> None:
    result = CliRunner().invoke(main, ["cache-contract", "schema", contract])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["additionalProperties"] is False
