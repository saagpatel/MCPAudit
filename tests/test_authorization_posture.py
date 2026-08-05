"""Contract and boundary tests for offline authorization-posture adoption."""

from __future__ import annotations

import json
import socket
import traceback
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mcp_audit.authorization_posture_models import (
    AuthorizationPostureReport,
    McpAuthorizationPostureV1,
)
from mcp_audit.authorization_posture_scanner import (
    AuthorizationPostureInputError,
    parse_authorization_posture_bytes,
    report_json_bytes,
    review_authorization_posture_path,
)
from mcp_audit.cli import main


def _freshness() -> dict[str, Any]:
    return {
        "state": "current",
        "http_date": "2026-08-05T11:34:20Z",
        "last_modified": None,
        "cache_control": "public, max-age=60",
        "age_header_seconds": None,
        "effective_age_seconds": 0.0,
        "policy_freshness_seconds": 60,
    }


def _ready_payload() -> dict[str, Any]:
    resource = "https://mcp.vendor.example/service"
    issuer = "https://auth.vendor.example/"
    resource_metadata_url = "https://mcp.vendor.example/.well-known/oauth-protected-resource/service"
    authorization_metadata_url = "https://auth.vendor.example/.well-known/oauth-authorization-server"
    return {
        "schema_version": "McpAuthorizationPostureV1",
        "contract_version": "1.0.0",
        "observed_at": "2026-08-05T11:34:19Z",
        "specification": {
            "profile": "mcp-authorization-2025-11-25",
            "references": [
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                "https://datatracker.ietf.org/doc/html/rfc9728",
                "https://datatracker.ietf.org/doc/html/rfc8414",
                "https://openid.net/specs/openid-connect-discovery-1_0.html",
            ],
        },
        "binding": {
            "stable_id": "example-vendor-service-1-0-0",
            "resource_url": resource,
            "manifest_sha256": "a" * 64,
            "source_kind": "official-mcp-registry-export",
        },
        "state": "metadata-ready",
        "scan_eligibility": "policy-review-only",
        "authorization_required": None,
        "challenge_scopes": [],
        "resource_metadata": {
            "resource": resource,
            "authorization_servers": [issuer],
            "scopes_supported": ["read", "write"],
            "metadata_url": resource_metadata_url,
            "discovery": "well-known-path",
        },
        "authorization_servers": [
            {
                "issuer": issuer,
                "state": "metadata-ready",
                "metadata_url": authorization_metadata_url,
                "discovery": "rfc8414",
                "metadata": {
                    "issuer": issuer,
                    "authorization_endpoint": "https://auth.vendor.example/authorize",
                    "token_endpoint": "https://auth.vendor.example/token",
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["read", "write"],
                    "client_id_metadata_document_supported": True,
                    "registration_endpoint": "https://auth.vendor.example/register",
                },
                "reason_codes": ["metadata_ready"],
            }
        ],
        "fetches": [
            {
                "kind": "resource-metadata:well-known-path",
                "url": resource_metadata_url,
                "status": 200,
                "content_type": "application/json",
                "body_bytes": 160,
                "body_sha256": "b" * 64,
                "freshness": _freshness(),
                "state": "validated",
                "reason_code": "resource_metadata_valid",
            },
            {
                "kind": "authorization-server:rfc8414",
                "url": authorization_metadata_url,
                "status": 200,
                "content_type": "application/json",
                "body_bytes": 480,
                "body_sha256": "c" * 64,
                "freshness": _freshness(),
                "state": "validated",
                "reason_code": "authorization_server_metadata_valid",
            },
        ],
        "reason_codes": ["metadata_ready"],
        "capability_boundary": {
            "network_methods": ["GET"],
            "credentials_supported": False,
            "proxy_environment_used": False,
            "redirects_followed": False,
            "dns_addresses_pinned": True,
            "non_public_addresses_allowed": False,
            "mutation_capabilities": [],
        },
        "claim_ceiling": {
            "authorization_proven": False,
            "credentials_available": False,
            "trust_grade_authority": False,
            "runtime_security_proven": False,
        },
    }


def _unknown_payload() -> dict[str, Any]:
    payload = _ready_payload()
    payload["state"] = "unknown"
    payload["scan_eligibility"] = "blocked"
    payload["resource_metadata"] = None
    payload["authorization_servers"] = []
    payload["reason_codes"] = ["metadata_not_found"]
    payload["fetches"] = [
        {
            "kind": "resource-metadata:well-known-path",
            "url": "https://mcp.vendor.example/.well-known/oauth-protected-resource/service",
            "status": 404,
            "content_type": "application/json",
            "body_bytes": None,
            "body_sha256": None,
            "freshness": {
                "state": "unknown",
                "http_date": None,
                "last_modified": None,
                "cache_control": None,
                "age_header_seconds": None,
                "effective_age_seconds": None,
                "policy_freshness_seconds": None,
            },
            "state": "unknown",
            "reason_code": "metadata_not_found",
        }
    ]
    return payload


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_metadata_ready_input_projects_only_policy_review(tmp_path: Path) -> None:
    source = tmp_path / "posture.json"
    _write(source, _ready_payload())
    report = review_authorization_posture_path(source)

    assert report.disposition == "policy-review-only"
    assert report.metadata_state == "producer-declared-ready"
    assert report.authorization_servers.declared == 1
    assert report.authorization_servers.metadata_ready == 1
    assert report.findings[0].rule_id == "MCPPOSTURE001"
    assert report.findings[0].outcome == "advisory"
    assert report.authority_flow.input_provenance == "unverified"
    assert report.authority_flow.input_freshness == "unverified"
    assert report.authority_flow.network_used is False
    assert report.authority_flow.credentials_used is False
    assert report.authority_flow.endpoint_session_used is False
    assert report.authority_flow.scan_authorized is False
    assert report.authority_flow.trust_grade_changed is False


def test_unknown_input_remains_blocked(tmp_path: Path) -> None:
    source = tmp_path / "posture.json"
    _write(source, _unknown_payload())
    report = review_authorization_posture_path(source)

    assert report.disposition == "blocked"
    assert report.metadata_state == "producer-declared-unknown"
    assert report.findings[0].rule_id == "MCPPOSTURE000"
    assert report.findings[0].outcome == "unknown"
    assert report.findings[0].evidence == ["producer reason code: metadata_not_found"]


def test_report_is_canonical_deterministic_and_omits_fetch_details(tmp_path: Path) -> None:
    source = tmp_path / "posture.json"
    _write(source, _ready_payload())
    first = report_json_bytes(review_authorization_posture_path(source))
    second = report_json_bytes(review_authorization_posture_path(source))

    assert first == second
    assert first.endswith(b"\n")
    assert b"authorization_endpoint" not in first
    assert b"token_endpoint" not in first
    assert "fetches" not in json.loads(first)
    AuthorizationPostureReport.model_validate_json(first, strict=True)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), "McpAuthorizationPostureV2"),
        (("contract_version",), "2.0.0"),
        (("scan_eligibility",), "blocked"),
        (("capability_boundary", "credentials_supported"), True),
        (("capability_boundary", "proxy_environment_used"), True),
        (("capability_boundary", "redirects_followed"), True),
        (("capability_boundary", "dns_addresses_pinned"), False),
        (("capability_boundary", "non_public_addresses_allowed"), True),
        (("capability_boundary", "mutation_capabilities"), ["never"]),
        (("claim_ceiling", "authorization_proven"), True),
        (("claim_ceiling", "credentials_available"), True),
        (("claim_ceiling", "trust_grade_authority"), True),
        (("claim_ceiling", "runtime_security_proven"), True),
        (("binding", "resource_url"), "https://localhost/service"),
        (("binding", "resource_url"), "https://127.0.0.1/service"),
        (("binding", "resource_url"), "https://mcp.vendor.example/%5cprivate"),
    ],
)
def test_widened_or_incompatible_producer_contract_is_rejected(
    path: tuple[str, ...],
    value: object,
) -> None:
    payload = _ready_payload()
    target: dict[str, Any] = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(payload).encode())


def test_cross_field_binding_and_state_drift_are_rejected() -> None:
    resource_mismatch = _ready_payload()
    resource_mismatch["resource_metadata"]["resource"] = "https://other.vendor.example/service"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(resource_mismatch).encode())

    issuer_mismatch = _ready_payload()
    issuer_mismatch["authorization_servers"][0]["issuer"] = "https://other.vendor.example/"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(issuer_mismatch).encode())

    unknown_with_ready_server = _ready_payload()
    unknown_with_ready_server["state"] = "unknown"
    unknown_with_ready_server["scan_eligibility"] = "blocked"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(unknown_with_ready_server).encode())

    missing_fetch_evidence = _ready_payload()
    missing_fetch_evidence["fetches"] = []
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(missing_fetch_evidence).encode())

    discovery_drift = _ready_payload()
    discovery_drift["authorization_servers"][0]["discovery"] = "openid-connect"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(discovery_drift).encode())

    reason_drift = _ready_payload()
    reason_drift["reason_codes"].append("authorization_server_partial")
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(reason_drift).encode())


def test_unknown_or_validated_fetch_cannot_claim_the_other_state() -> None:
    invalid_success = _ready_payload()
    invalid_success["fetches"][0]["state"] = "unknown"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(invalid_success).encode())

    false_success = _unknown_payload()
    false_success["fetches"][0]["reason_code"] = "resource_metadata_valid"
    with pytest.raises(AuthorizationPostureInputError, match="schema validation failed"):
        parse_authorization_posture_bytes(json.dumps(false_success).encode())


def test_duplicate_extra_deep_and_oversized_input_are_rejected() -> None:
    raw = json.dumps(_ready_payload()).encode()
    duplicate = raw.replace(
        b'"schema_version": "McpAuthorizationPostureV1"',
        b'"schema_version": "McpAuthorizationPostureV1", "schema_version": "McpAuthorizationPostureV1"',
        1,
    )
    with pytest.raises(AuthorizationPostureInputError, match="invalid JSON posture"):
        parse_authorization_posture_bytes(duplicate)

    extra = _ready_payload()
    extra["authorization_token"] = "SYNTHETIC_SECRET_DO_NOT_REFLECT"
    with pytest.raises(AuthorizationPostureInputError) as captured:
        parse_authorization_posture_bytes(json.dumps(extra).encode())
    assert "SYNTHETIC_SECRET" not in str(captured.value)
    assert "SYNTHETIC_SECRET" not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None

    with pytest.raises(AuthorizationPostureInputError, match="nesting exceeds"):
        parse_authorization_posture_bytes(("[" * 33 + "]" * 33).encode())

    with pytest.raises(AuthorizationPostureInputError, match="exceeds 1048576 bytes"):
        parse_authorization_posture_bytes(b" " * 1_048_577)


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "posture.json"
    alias = tmp_path / "alias.json"
    _write(source, _ready_payload())
    alias.symlink_to(source)

    with pytest.raises(AuthorizationPostureInputError, match="non-symlink"):
        review_authorization_posture_path(alias)


def test_review_uses_no_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "posture.json"
    _write(source, _ready_payload())

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "socket", denied)
    assert review_authorization_posture_path(source).disposition == "policy-review-only"


def test_cli_exit_contract_and_safe_artifact_writes(tmp_path: Path) -> None:
    runner = CliRunner()
    ready = tmp_path / "ready.json"
    unknown = tmp_path / "unknown.json"
    invalid = tmp_path / "invalid.json"
    report_path = tmp_path / "report.json"
    _write(ready, _ready_payload())
    _write(unknown, _unknown_payload())
    invalid.write_text('{"sentinel":"SYNTHETIC_SECRET_DO_NOT_REFLECT"}', encoding="utf-8")

    ready_result = runner.invoke(main, ["authorization-posture", "review", str(ready)])
    assert ready_result.exit_code == 0
    assert json.loads(ready_result.output)["disposition"] == "policy-review-only"

    unknown_result = runner.invoke(main, ["authorization-posture", "review", str(unknown)])
    assert unknown_result.exit_code == 1
    assert json.loads(unknown_result.output)["disposition"] == "blocked"

    invalid_result = runner.invoke(main, ["authorization-posture", "review", str(invalid)])
    assert invalid_result.exit_code == 2
    assert "SYNTHETIC_SECRET" not in invalid_result.output
    assert invalid_result.exception is not None
    assert "SYNTHETIC_SECRET" not in "".join(traceback.format_exception(invalid_result.exception))

    written = runner.invoke(
        main,
        ["authorization-posture", "review", str(ready), "--json", str(report_path)],
    )
    assert written.exit_code == 0
    assert written.output == ""
    assert json.loads(report_path.read_text(encoding="utf-8"))["disposition"] == "policy-review-only"

    no_clobber = runner.invoke(
        main,
        ["authorization-posture", "review", str(ready), "--json", str(report_path)],
    )
    assert no_clobber.exit_code == 2
    forced = runner.invoke(
        main,
        [
            "authorization-posture",
            "review",
            str(ready),
            "--json",
            str(report_path),
            "--force",
        ],
    )
    assert forced.exit_code == 0


def test_cli_refuses_input_output_alias(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "posture.json"
    _write(source, _ready_payload())
    result = runner.invoke(
        main,
        [
            "authorization-posture",
            "review",
            str(source),
            "--json",
            str(source),
            "--force",
        ],
    )
    assert result.exit_code == 2
    assert "must not alias" in result.output
    McpAuthorizationPostureV1.model_validate_json(source.read_bytes(), strict=True)


def test_schema_commands_are_strict_and_versioned() -> None:
    runner = CliRunner()
    input_result = runner.invoke(main, ["authorization-posture", "schema", "input"])
    report_result = runner.invoke(main, ["authorization-posture", "schema", "report"])
    assert input_result.exit_code == report_result.exit_code == 0
    input_schema = json.loads(input_result.output)
    report_schema = json.loads(report_result.output)
    assert input_schema["additionalProperties"] is False
    assert input_schema["properties"]["schema_version"]["const"] == "McpAuthorizationPostureV1"
    assert report_schema["additionalProperties"] is False
    assert (
        report_schema["properties"]["schema_version"]["const"] == "mcpaudit.authorization-posture.report.v1"
    )


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("authorization-posture-input-v1.schema.json", McpAuthorizationPostureV1),
        ("authorization-posture-report-v1.schema.json", AuthorizationPostureReport),
    ],
)
def test_checked_in_schemas_match_live_models(
    filename: str,
    model: type[McpAuthorizationPostureV1] | type[AuthorizationPostureReport],
) -> None:
    checked_in = json.loads((Path("examples/schemas") / filename).read_text(encoding="utf-8"))
    assert checked_in == model.model_json_schema()


def test_input_model_rejects_non_strict_types() -> None:
    payload = deepcopy(_ready_payload())
    payload["fetches"][0]["status"] = "200"
    with pytest.raises(ValidationError):
        McpAuthorizationPostureV1.model_validate(payload, strict=True)
