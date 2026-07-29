"""Generate the checked-in synthetic OAuth transcript fixture corpus."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from mcp_audit.oauth_transcript_models import OAuthTranscriptFixture, OAuthTranscriptReport

ROOT = Path(__file__).parents[1] / "tests" / "fixtures" / "oauth_transcript"
SCHEMA_ROOT = Path(__file__).parents[1] / "examples" / "schemas"

RESOURCE = "https://mcp.example/mcp"
OTHER_RESOURCE = "https://api.example/data"
AUTHORITY = "https://auth.example"
OTHER_AUTHORITY = "https://other-auth.example"
METADATA = "https://mcp.example/.well-known/oauth-protected-resource/mcp"
METADATA_V2 = "https://mcp.example/.well-known/oauth-protected-resource/mcp-v2"
REDIRECT = "http://127.0.0.1:43119/callback"
REDIRECT_OTHER = "http://127.0.0.1:43119/other"
REDIRECT_EPHEMERAL = "http://127.0.0.1:49152/callback"


def base(fixture_id: str, control_kind: str) -> dict[str, Any]:
    return {
        "schema_version": "mcpaudit.oauth-transcript.fixture.v1",
        "program_owned": True,
        "synthetic": True,
        "fixture_id": fixture_id,
        "control_kind": control_kind,
        "spec_profile": "mcp-authorization-2025-11-25+draft-2026-07-28",
        "intended_resource": RESOURCE,
        "intended_authorization_server": AUTHORITY,
        "registration": {
            "method": "dynamic_client_registration",
            "client_kind": "native",
            "application_type": "native",
            "issuer": AUTHORITY,
            "redirect_uris": [REDIRECT],
            "pre_registered_available": False,
        },
        "credential_records": [
            {
                "record_id": "synthetic-dcr-client",
                "method": "dynamic_client_registration",
                "issuer": AUTHORITY,
                "client_id_marker": "SYNTHETIC_CLIENT_ID",
                "client_secret_marker": "<redacted>",
            }
        ],
        "audience_evidence": {
            "state": "current",
            "source": "synthetic_introspection",
            "token_response_exchange_id": "token-response",
            "audiences": [RESOURCE],
            "accepted_for_resource": RESOURCE,
        },
        "scope_context": {
            "reauthorization": False,
            "previously_granted_scopes": [],
        },
        "observations": [
            {
                "kind": "protected_resource_challenge",
                "exchange_id": "resource-challenge",
                "sequence": 1,
                "redirects_followed": 0,
                "request_url": RESOURCE,
                "response_status": 401,
                "resource_metadata_url": METADATA,
                "scopes": ["mcp.read"],
            },
            {
                "kind": "protected_resource_metadata",
                "exchange_id": "resource-metadata",
                "sequence": 2,
                "redirects_followed": 0,
                "request_url": METADATA,
                "response_status": 200,
                "document_state": "complete",
                "resource": RESOURCE,
                "authorization_servers": [AUTHORITY],
                "scopes_supported": ["mcp.read", "mcp.write"],
            },
            {
                "kind": "authorization_server_metadata",
                "exchange_id": "authorization-metadata",
                "sequence": 3,
                "redirects_followed": 0,
                "request_url": f"{AUTHORITY}/.well-known/oauth-authorization-server",
                "response_status": 200,
                "document_state": "complete",
                "metadata_kind": "oauth",
                "issuer": AUTHORITY,
                "authorization_endpoint": f"{AUTHORITY}/authorize",
                "token_endpoint": f"{AUTHORITY}/token",
                "registration_endpoint": f"{AUTHORITY}/register",
                "client_id_metadata_document_supported": False,
                "authorization_response_iss_parameter_supported": True,
            },
            {
                "kind": "authorization_request",
                "exchange_id": "authorization-request",
                "sequence": 4,
                "redirects_followed": 0,
                "request_url": f"{AUTHORITY}/authorize",
                "resources": [RESOURCE],
                "scopes": ["mcp.read"],
                "recorded_issuer": AUTHORITY,
                "redirect_uri": REDIRECT,
                "client_id_kind": "opaque",
            },
            {
                "kind": "authorization_response",
                "exchange_id": "authorization-response",
                "sequence": 5,
                "redirects_followed": 1,
                "response_status": 302,
                "redirect_uri": REDIRECT,
                "issuer": AUTHORITY,
                "code_marker": "<redacted>",
                "handling": "accepted",
            },
            {
                "kind": "token_request",
                "exchange_id": "token-request",
                "sequence": 6,
                "redirects_followed": 0,
                "request_url": f"{AUTHORITY}/token",
                "grant_type": "authorization_code",
                "code_marker": "<redacted>",
                "redirect_uri": REDIRECT,
                "resources": [RESOURCE],
                "scopes": ["mcp.read"],
                "credential_record_id": "synthetic-dcr-client",
            },
            {
                "kind": "token_response",
                "exchange_id": "token-response",
                "sequence": 7,
                "redirects_followed": 0,
                "response_status": 200,
                "access_token_marker": "<redacted>",
                "scopes": ["mcp.read"],
            },
            {
                "kind": "protected_resource_use",
                "exchange_id": "resource-use",
                "sequence": 8,
                "redirects_followed": 0,
                "request_url": RESOURCE,
                "authorization_marker": "<redacted>",
                "response_status": 200,
            },
        ],
    }


def fixture(rule: int, control: str) -> dict[str, Any]:
    payload = base(f"mcpoauth{rule:03d}-{control}", control)
    if rule == 0:
        if control == "vulnerable":
            payload["audience_evidence"] = {
                "state": "missing",
                "source": "none",
                "token_response_exchange_id": None,
                "audiences": [],
                "accepted_for_resource": None,
            }
        elif control == "near_miss":
            metadata = payload["observations"][1]
            metadata["document_state"] = "malformed"
            metadata["resource"] = None
            metadata["authorization_servers"] = []
            metadata["scopes_supported"] = None
    elif rule == 1:
        if control == "vulnerable":
            payload["observations"][0]["resource_metadata_url"] = METADATA_V2
        elif control == "near_miss":
            payload["observations"][1]["authorization_servers"] = [AUTHORITY, OTHER_AUTHORITY]
    elif rule == 2:
        if control == "vulnerable":
            payload["observations"][5]["resources"] = [OTHER_RESOURCE]
        elif control == "near_miss":
            payload["observations"][3]["resources"] = [RESOURCE, OTHER_RESOURCE]
    elif rule == 3:
        if control == "vulnerable":
            payload["observations"][4]["issuer"] = OTHER_AUTHORITY
        elif control == "near_miss":
            payload["observations"][2]["authorization_response_iss_parameter_supported"] = False
            payload["observations"][4]["issuer"] = None
    elif rule == 4:
        if control == "vulnerable":
            payload["credential_records"][0]["issuer"] = OTHER_AUTHORITY
        elif control == "near_miss":
            payload["registration"] = {
                "method": "client_id_metadata_document",
                "client_kind": "native",
                "application_type": None,
                "issuer": None,
                "redirect_uris": [REDIRECT],
                "pre_registered_available": False,
            }
            payload["credential_records"] = []
            payload["observations"][2]["client_id_metadata_document_supported"] = True
            payload["observations"][3]["client_id_kind"] = "https_metadata_url"
            payload["observations"][5]["credential_record_id"] = None
    elif rule == 5:
        if control == "vulnerable":
            payload["registration"]["application_type"] = "web"
        elif control == "near_miss":
            payload["registration"] = {
                "method": "pre_registered",
                "client_kind": "native",
                "application_type": None,
                "issuer": AUTHORITY,
                "redirect_uris": [REDIRECT],
                "pre_registered_available": True,
            }
            payload["credential_records"][0]["method"] = "pre_registered"
    elif rule == 6:
        if control == "vulnerable":
            payload["observations"][3]["scopes"] = ["mcp.read", "mcp.admin"]
        elif control == "near_miss":
            payload["scope_context"] = {
                "reauthorization": True,
                "previously_granted_scopes": ["mcp.write"],
            }
            payload["observations"][3]["scopes"] = ["mcp.read", "mcp.write"]
            payload["observations"][5]["scopes"] = ["mcp.read", "mcp.write"]
            payload["observations"][6]["scopes"] = ["mcp.read", "mcp.write"]
    elif rule == 7:
        if control == "vulnerable":
            payload["observations"][5]["redirect_uri"] = REDIRECT_OTHER
        elif control == "near_miss":
            payload["observations"][3]["redirect_uri"] = REDIRECT_EPHEMERAL
            payload["observations"][4]["redirect_uri"] = REDIRECT_EPHEMERAL
            payload["observations"][5]["redirect_uri"] = REDIRECT_EPHEMERAL
    return payload


def write_fixture(name: str, payload: dict[str, Any]) -> None:
    (ROOT / name).write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    for rule in range(8):
        for control in ("vulnerable", "negative", "near_miss"):
            write_fixture(f"mcpoauth{rule:03d}-{control}.json", fixture(rule, control))

    wrong_resource = base("wrong-resource-special", "special")
    wrong_resource["observations"][1]["resource"] = OTHER_RESOURCE
    write_fixture("wrong-resource-special.json", wrong_resource)

    wrong_audience_rejected = base("wrong-audience-rejected-special", "special")
    wrong_audience_rejected["audience_evidence"]["audiences"] = [OTHER_RESOURCE]
    wrong_audience_rejected["audience_evidence"]["accepted_for_resource"] = None
    wrong_audience_rejected["observations"][7]["response_status"] = 401
    write_fixture("wrong-audience-rejected-special.json", wrong_audience_rejected)

    wrong_audience_accepted = base("wrong-audience-accepted-special", "special")
    wrong_audience_accepted["audience_evidence"]["audiences"] = [OTHER_RESOURCE]
    write_fixture("wrong-audience-accepted-special.json", wrong_audience_accepted)

    credential_looking = copy.deepcopy(base("credential-looking-rejected", "special"))
    credential_looking["access_token"] = "SYNTHETIC_SECRET_DO_NOT_LEAK_7f6ab42"
    rejected = ROOT / "rejected"
    rejected.mkdir(exist_ok=True)
    (rejected / "credential-looking.json").write_text(
        json.dumps(credential_looking, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    schemas = {
        "oauth-transcript-fixture-v1.schema.json": OAuthTranscriptFixture,
        "oauth-transcript-report-v1.schema.json": OAuthTranscriptReport,
    }
    for name, model in schemas.items():
        (SCHEMA_ROOT / name).write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
