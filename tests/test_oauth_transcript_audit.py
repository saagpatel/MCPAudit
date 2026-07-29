"""Fixture-first tests for the offline MCP OAuth transcript auditor."""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import BaseModel, ValidationError

from mcp_audit.cli import main
from mcp_audit.oauth_transcript_models import OAuthTranscriptFixture, OAuthTranscriptReport
from mcp_audit.oauth_transcript_sarif import oauth_report_to_sarif
from mcp_audit.oauth_transcript_scanner import (
    OAuthTranscriptInputError,
    parse_oauth_transcript_bytes,
    report_json_bytes,
    scan_oauth_transcript_path,
)

FIXTURE_ROOT = Path("tests/fixtures/oauth_transcript")
SENTINEL_SECRET = "SYNTHETIC_SECRET_DO_NOT_LEAK_7f6ab42"


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / name


def _payload(name: str) -> dict[str, Any]:
    value = json.loads(_fixture(name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _semantic_diff_count(first: Any, second: Any, path: tuple[str, ...] = ()) -> int:
    if path == ("audience_evidence",):
        return int(first != second)
    if type(first) is not type(second):
        return 1
    if isinstance(first, dict):
        keys = set(first) | set(second)
        return sum(_semantic_diff_count(first.get(key), second.get(key), (*path, key)) for key in keys)
    if isinstance(first, list):
        return int(first != second)
    return int(first != second)


def test_fixture_inventory_has_vulnerable_negative_near_miss_triplets() -> None:
    triplets = [path for path in FIXTURE_ROOT.glob("mcpoauth*.json") if path.parent == FIXTURE_ROOT]
    assert len(triplets) == 21
    for rule in range(7):
        prefix = f"mcpoauth{rule:03d}-"
        members = sorted(path.name for path in triplets if path.name.startswith(prefix))
        assert members == [
            f"{prefix}near_miss.json",
            f"{prefix}negative.json",
            f"{prefix}vulnerable.json",
        ]


@pytest.mark.parametrize("rule", range(7))
def test_each_vulnerable_control_fires_only_its_stable_rule(rule: int) -> None:
    report = scan_oauth_transcript_path(_fixture(f"mcpoauth{rule:03d}-vulnerable.json"))
    expected = f"MCPOAUTH{rule:03d}"
    material = [item for item in report.findings if item.outcome.value != "advisory"]
    assert {item.rule_id for item in material} == {expected}
    assert report.verdict == ("unknown" if rule == 0 else "fail")
    for finding in material:
        assert finding.evidence
        assert finding.remediation
        assert finding.references
        assert finding.assumptions


@pytest.mark.parametrize("rule", range(7))
def test_each_negative_control_changes_one_semantic_binding_and_clears_the_rule(rule: int) -> None:
    vulnerable = _payload(f"mcpoauth{rule:03d}-vulnerable.json")
    negative = _payload(f"mcpoauth{rule:03d}-negative.json")
    for ignored in ("fixture_id", "control_kind"):
        vulnerable.pop(ignored)
        negative.pop(ignored)
    assert _semantic_diff_count(vulnerable, negative) == 1
    report = scan_oauth_transcript_path(_fixture(f"mcpoauth{rule:03d}-negative.json"))
    assert report.verdict == "pass"
    assert all(item.outcome.value == "advisory" for item in report.findings)


@pytest.mark.parametrize("rule", range(1, 7))
def test_near_misses_do_not_create_false_violations(rule: int) -> None:
    report = scan_oauth_transcript_path(_fixture(f"mcpoauth{rule:03d}-near_miss.json"))
    assert report.verdict == "pass"
    assert all(item.outcome.value == "advisory" for item in report.findings)


def test_missing_and_malformed_evidence_are_unknown_not_pass() -> None:
    missing = scan_oauth_transcript_path(_fixture("mcpoauth000-vulnerable.json"))
    malformed = scan_oauth_transcript_path(_fixture("mcpoauth000-near_miss.json"))
    assert missing.verdict == "unknown"
    assert malformed.verdict == "unknown"
    assert {item.rule_id for item in missing.findings if item.outcome.value == "unknown"} == {"MCPOAUTH000"}
    assert {item.rule_id for item in malformed.findings if item.outcome.value == "unknown"} == {"MCPOAUTH000"}


def test_required_named_security_scenarios_are_covered() -> None:
    stale = scan_oauth_transcript_path(_fixture("mcpoauth001-vulnerable.json"))
    wrong_resource = scan_oauth_transcript_path(_fixture("wrong-resource-special.json"))
    issuer_mixup = scan_oauth_transcript_path(_fixture("mcpoauth003-vulnerable.json"))
    credential_reuse = scan_oauth_transcript_path(_fixture("mcpoauth004-vulnerable.json"))
    scope_mismatch = scan_oauth_transcript_path(_fixture("mcpoauth006-vulnerable.json"))
    assert [item.rule_id for item in stale.findings if item.outcome.value == "violation"] == ["MCPOAUTH001"]
    assert [item.rule_id for item in wrong_resource.findings if item.outcome.value == "violation"] == [
        "MCPOAUTH001"
    ]
    assert [item.rule_id for item in issuer_mixup.findings if item.outcome.value == "violation"] == [
        "MCPOAUTH003"
    ]
    assert [item.rule_id for item in credential_reuse.findings if item.outcome.value == "violation"] == [
        "MCPOAUTH004"
    ]
    assert [item.rule_id for item in scope_mismatch.findings if item.outcome.value == "violation"] == [
        "MCPOAUTH006"
    ]


def test_valid_multi_resource_subset_and_wrong_audience_rejection_are_safe() -> None:
    multi_resource = scan_oauth_transcript_path(_fixture("mcpoauth002-near_miss.json"))
    rejected = scan_oauth_transcript_path(_fixture("wrong-audience-rejected-special.json"))
    assert multi_resource.verdict == "pass"
    assert rejected.verdict == "pass"
    assert not any(item.rule_id == "MCPOAUTH002" for item in rejected.findings)


def test_wrong_audience_acceptance_fails_and_missing_intended_decision_is_unknown(
    tmp_path: Path,
) -> None:
    accepted = scan_oauth_transcript_path(_fixture("wrong-audience-accepted-special.json"))
    assert accepted.verdict == "fail"
    assert "MCPOAUTH002" in {item.rule_id for item in accepted.findings if item.outcome.value == "violation"}

    payload = _payload("mcpoauth002-negative.json")
    payload["fixture_id"] = "intended-audience-decision-missing"
    payload["audience_evidence"]["accepted_for_resource"] = None
    payload["observations"].pop()
    path = tmp_path / "no-intended-decision.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "unknown"
    assert "MCPOAUTH000" in {item.rule_id for item in report.findings if item.outcome.value == "unknown"}

    outside_request = _payload("mcpoauth002-near_miss.json")
    outside_request["fixture_id"] = "accepted-outside-token-request"
    outside_request["audience_evidence"]["audiences"] = [
        "https://mcp.example/mcp",
        "https://api.example/data",
    ]
    outside_request["audience_evidence"]["accepted_for_resource"] = "https://api.example/data"
    outside_request["observations"][7]["request_url"] = "https://api.example/data"
    path = tmp_path / "outside-token-request.json"
    path.write_text(json.dumps(outside_request), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "fail"
    assert "MCPOAUTH002" in {item.rule_id for item in report.findings if item.outcome.value == "violation"}


def test_safe_deprecated_dcr_fallback_is_advisory_not_forbidden() -> None:
    report = scan_oauth_transcript_path(_fixture("mcpoauth005-negative.json"))
    dcr = [item for item in report.findings if item.rule_id == "MCPOAUTH005"]
    assert report.verdict == "pass"
    assert len(dcr) == 1
    assert dcr[0].outcome.value == "advisory"
    assert dcr[0].requirement_level.value == "deprecated"
    assert "backwards-compatible fallback" in dcr[0].evidence[0]


def test_user_supplied_persisted_client_state_is_still_issuer_bound(tmp_path: Path) -> None:
    payload = _payload("mcpoauth004-negative.json")
    payload["fixture_id"] = "user-supplied-issuer-change"
    payload["registration"]["method"] = "user_supplied"
    payload["credential_records"][0]["method"] = "user_supplied"
    payload["credential_records"][0]["issuer"] = "https://other-auth.example"
    path = tmp_path / "user-supplied.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "fail"
    assert "MCPOAUTH004" in {item.rule_id for item in report.findings if item.outcome.value == "violation"}


def test_oidc_application_type_redirect_constraints_are_observable(tmp_path: Path) -> None:
    payload = _payload("mcpoauth005-negative.json")
    payload["fixture_id"] = "oidc-native-web-redirect"
    metadata = payload["observations"][2]
    metadata["metadata_kind"] = "openid_connect"
    metadata["request_url"] = "https://auth.example/.well-known/openid-configuration"
    payload["registration"]["redirect_uris"] = ["https://client.example/callback"]
    path = tmp_path / "oidc-redirect.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "fail"
    assert "MCPOAUTH005" in {item.rule_id for item in report.findings if item.outcome.value == "violation"}


def test_report_is_deterministic_strict_and_redacted() -> None:
    path = _fixture("mcpoauth003-vulnerable.json")
    first = scan_oauth_transcript_path(path)
    second = scan_oauth_transcript_path(path)
    first_bytes = report_json_bytes(first)
    assert first == second
    assert first_bytes == report_json_bytes(second)
    assert first_bytes.endswith(b"\n")
    assert OAuthTranscriptReport.model_validate_json(first_bytes, strict=True) == first
    output = first_bytes.decode()
    assert "other-auth.example" not in output
    assert "<redacted>" not in output


def test_credential_looking_input_is_rejected_without_reflection() -> None:
    path = _fixture("rejected/credential-looking.json")
    raw = path.read_bytes()
    assert SENTINEL_SECRET.encode() in raw
    with pytest.raises(OAuthTranscriptInputError) as caught:
        parse_oauth_transcript_bytes(raw)
    assert "credential-looking input rejected" in str(caught.value)
    assert SENTINEL_SECRET not in str(caught.value)
    result = CliRunner().invoke(main, ["oauth-transcript", "scan", str(path)])
    assert result.exit_code == 2
    assert SENTINEL_SECRET not in result.output
    assert SENTINEL_SECRET not in (result.exception and str(result.exception) or "")

    secret_field = _payload("mcpoauth001-negative.json")
    secret_field[SENTINEL_SECRET] = True
    with pytest.raises(OAuthTranscriptInputError) as secret_field_error:
        parse_oauth_transcript_bytes(json.dumps(secret_field).encode())
    assert SENTINEL_SECRET not in str(secret_field_error.value)


def test_duplicate_keys_and_symlink_inputs_are_rejected() -> None:
    raw = _fixture("mcpoauth001-negative.json").read_bytes()
    duplicate = raw.replace(b'"program_owned": true,', b'"program_owned": true, "program_owned": true,')
    with pytest.raises(OAuthTranscriptInputError, match="invalid JSON fixture"):
        parse_oauth_transcript_bytes(duplicate)


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    link = tmp_path / "fixture.json"
    link.symlink_to(_fixture("mcpoauth001-negative.json").resolve())
    with pytest.raises(OAuthTranscriptInputError, match="non-symlink"):
        scan_oauth_transcript_path(link)


def test_strict_schema_rejects_unknown_fields() -> None:
    payload = _payload("mcpoauth001-negative.json")
    payload["unknown"] = True
    with pytest.raises(ValidationError):
        OAuthTranscriptFixture.model_validate(payload, strict=True)


def test_issuer_query_and_unbound_audience_evidence_do_not_pass(tmp_path: Path) -> None:
    query_issuer = _payload("mcpoauth001-negative.json")
    query_issuer["intended_authorization_server"] = "https://auth.example?tenant=synthetic"
    with pytest.raises(OAuthTranscriptInputError, match="schema validation failed"):
        parse_oauth_transcript_bytes(json.dumps(query_issuer).encode())

    unbound = _payload("mcpoauth002-negative.json")
    unbound["fixture_id"] = "unbound-audience-evidence"
    unbound["audience_evidence"]["token_response_exchange_id"] = "other-token-response"
    path = tmp_path / "unbound-audience.json"
    path.write_text(json.dumps(unbound), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "unknown"
    assert "MCPOAUTH000" in {item.rule_id for item in report.findings if item.outcome.value == "unknown"}


def test_cimd_selection_requires_a_metadata_url_client_identifier(tmp_path: Path) -> None:
    payload = _payload("mcpoauth004-near_miss.json")
    payload["fixture_id"] = "cimd-opaque-client-id"
    payload["observations"][3]["client_id_kind"] = "opaque"
    path = tmp_path / "cimd-opaque.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "fail"
    assert "MCPOAUTH005" in {item.rule_id for item in report.findings if item.outcome.value == "violation"}


def test_multiple_flow_observations_are_unknown_not_first_match_pass(tmp_path: Path) -> None:
    payload = _payload("mcpoauth001-negative.json")
    payload["fixture_id"] = "ambiguous-token-request"
    duplicate = dict(payload["observations"][5])
    duplicate["exchange_id"] = "second-token-request"
    duplicate["sequence"] = 9
    payload["observations"].append(duplicate)
    path = tmp_path / "ambiguous.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "unknown"
    assert "MCPOAUTH000" in {item.rule_id for item in report.findings if item.outcome.value == "unknown"}


def test_contradictory_token_evidence_is_unknown(tmp_path: Path) -> None:
    payload = _payload("mcpoauth002-negative.json")
    payload["fixture_id"] = "failed-token-with-current-audience"
    payload["observations"][6]["response_status"] = 400
    payload["observations"][6]["access_token_marker"] = None
    path = tmp_path / "contradictory-token.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = scan_oauth_transcript_path(path)
    assert report.verdict == "unknown"
    assert "MCPOAUTH000" in {item.rule_id for item in report.findings if item.outcome.value == "unknown"}


@pytest.mark.parametrize(
    ("contract", "model", "schema_name"),
    [
        ("fixture", OAuthTranscriptFixture, "oauth-transcript-fixture-v1.schema.json"),
        ("report", OAuthTranscriptReport, "oauth-transcript-report-v1.schema.json"),
    ],
)
def test_schema_command_matches_live_strict_model(
    contract: str,
    model: type[BaseModel],
    schema_name: str,
) -> None:
    result = CliRunner().invoke(main, ["oauth-transcript", "schema", contract])
    assert result.exit_code == 0, result.output
    schema = json.loads(result.output)
    assert schema == model.model_json_schema()  # type: ignore[attr-defined]
    checked_in = json.loads((Path("examples/schemas") / schema_name).read_text(encoding="utf-8"))
    assert checked_in == schema
    assert schema["additionalProperties"] is False


def test_scanner_has_no_network_or_process_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"runtime effect attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert scan_oauth_transcript_path(_fixture("mcpoauth001-negative.json")).verdict == "pass"
    assert scan_oauth_transcript_path(_fixture("wrong-resource-special.json")).verdict == "fail"


def test_parser_enforces_nesting_and_redirect_budgets() -> None:
    deeply_nested = b'{"x":' * 33 + b"0" + b"}" * 33
    with pytest.raises(OAuthTranscriptInputError, match="nesting exceeds"):
        parse_oauth_transcript_bytes(deeply_nested)
    payload = _payload("mcpoauth001-negative.json")
    payload["observations"][0]["redirects_followed"] = 5
    payload["observations"][4]["redirects_followed"] = 1
    with pytest.raises(OAuthTranscriptInputError, match="schema validation failed"):
        parse_oauth_transcript_bytes(json.dumps(payload).encode())


def test_sarif_uses_existing_compatibility_shape_without_fixture_locations() -> None:
    report = scan_oauth_transcript_path(_fixture("mcpoauth003-vulnerable.json"))
    sarif = oauth_report_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-audit"
    assert {item["id"] for item in run["tool"]["driver"]["rules"]} == {
        f"MCPOAUTH{rule:03d}" for rule in range(7)
    }
    assert all("locations" not in item for item in run["results"])
    assert "other-auth.example" not in json.dumps(sarif)


@pytest.mark.parametrize(
    ("name", "expected_exit", "expected_verdict"),
    [
        ("mcpoauth001-negative.json", 0, "pass"),
        ("mcpoauth003-vulnerable.json", 1, "fail"),
        ("wrong-resource-special.json", 1, "fail"),
        ("mcpoauth004-vulnerable.json", 1, "fail"),
        ("mcpoauth000-near_miss.json", 1, "unknown"),
        ("mcpoauth000-vulnerable.json", 1, "unknown"),
    ],
)
def test_offline_cli_smoke_matrix(
    name: str,
    expected_exit: int,
    expected_verdict: str,
) -> None:
    result = CliRunner().invoke(main, ["oauth-transcript", "scan", str(_fixture(name))])
    assert result.exit_code == expected_exit, result.output
    report = OAuthTranscriptReport.model_validate_json(result.stdout_bytes, strict=True)
    assert report.verdict == expected_verdict


def test_cli_writes_json_and_sarif_and_refuses_implicit_overwrite(tmp_path: Path) -> None:
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    args = [
        "oauth-transcript",
        "scan",
        str(_fixture("mcpoauth001-negative.json")),
        "--json",
        str(json_path),
        "--sarif",
        str(sarif_path),
    ]
    runner = CliRunner()
    first = runner.invoke(main, args)
    assert first.exit_code == 0, first.output
    assert OAuthTranscriptReport.model_validate_json(json_path.read_bytes(), strict=True).verdict == "pass"
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    second = runner.invoke(main, args)
    assert second.exit_code == 2
    assert "use --force" in second.output
    forced = runner.invoke(main, [*args, "--force"])
    assert forced.exit_code == 0, forced.output
