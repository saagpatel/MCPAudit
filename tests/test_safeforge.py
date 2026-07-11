"""SafeForge Manifest v0 schema and semantic-gate tests."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_audit.safeforge import (
    RESEARCH_MVP_STAGE_ORDER,
    SafeForgeManifest,
    StageId,
    safeforge_manifest_json_schema,
    validate_safeforge_manifest,
)

_NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC).isoformat()
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64


def _producer(name: str = "mcp-audit") -> dict[str, object]:
    return {
        "name": name,
        "version": "0.1.0",
        "source": f"io.github.saagpatel/{name}",
        "revision": "abc1234",
        "dirty": False,
        "executable": name,
    }


def _artifact(artifact_id: str, digest: str = _DIGEST_A) -> dict[str, str]:
    return {
        "artifact_id": artifact_id,
        "media_type": "application/json",
        "digest": digest,
        "uri": f"evidence/{artifact_id}.json",
    }


def _stage(stage_id: StageId, *, attempt: int = 1, state: str = "passed") -> dict[str, object]:
    stage: dict[str, object] = {
        "stage_id": stage_id.value,
        "attempt": attempt,
        "state": state,
        "required": True,
        "producer": _producer(),
        "started_at": _NOW,
        "finished_at": _NOW if state not in {"pending", "running"} else None,
        "inputs": [],
        "outputs": [],
        "coverage": {"requested": [], "executed": [], "skipped": [], "unavailable": []},
        "finding_ids": [],
        "failure_codes": [],
        "limitations": [],
    }
    if state == "failed":
        stage["failure_codes"] = ["SF-TEST-FAILURE"]
    if state in {"skipped", "unknown", "stale", "blocked"}:
        stage["limitations"] = [f"test {state} state"]
    return stage


def _base_manifest() -> dict[str, Any]:
    return {
        "contract": {
            "contract_id": "safeforge.pipeline",
            "contract_version": "0.1.0",
            "profile": "research-mvp",
        },
        "run": {
            "run_id": "safeforge-echo-v1",
            "created_at": _NOW,
            "coordinator": _producer(),
            "decision": "building",
        },
        "subject": {
            "server_id": "safeforge-echo",
            "source_kind": "natural-language",
            "source_spec_digest": _DIGEST_A,
            "transport": "stdio",
            "mcp_protocol_supported": ["2025-11-25"],
            "mcp_protocol_negotiated": None,
        },
        "producers": [_producer("mcpforge"), _producer()],
        "artifact": {
            "tree_digest": _DIGEST_A,
            "files": [_artifact("generated-tree")],
            "dependency_manifest_digest": _DIGEST_B,
            "lockfile_digest": None,
            "package_identities": ["fastmcp>=3.1.0"],
        },
        "toolbom": [
            {
                "tool_id": "safeforge-echo#echo",
                "name": "echo",
                "description_digest": _DIGEST_A,
                "input_schema_digest": _DIGEST_B,
                "output_schema_digest": _DIGEST_C,
                "implementation_digest": _DIGEST_A,
                "observed_capabilities": [],
                "observed_egress_destinations": [],
                "annotations": {
                    "read_only": True,
                    "destructive": False,
                    "idempotent": True,
                    "open_world": False,
                },
                "declared": {
                    "permissions": [],
                    "auth_scopes": [],
                    "data_zones": [],
                    "egress_destinations": [],
                    "credential_keys": [],
                },
            }
        ],
        "stages": [_stage(StageId.SOURCE_BIND)],
        "sandbox": None,
        "audit": None,
        "policies": [],
        "grade": None,
        "publication": None,
        "integrity": None,
        "limitations": [],
    }


def _final_manifest() -> dict[str, object]:
    manifest = _base_manifest()
    manifest["run"]["decision"] = "eligible"
    manifest["stages"] = [_stage(stage_id) for stage_id in RESEARCH_MVP_STAGE_ORDER]
    manifest["sandbox"] = {
        "provider": "docker",
        "isolates": True,
        "image_digest": _DIGEST_A,
        "network": "none",
        "mounts": [],
        "credential_mode": "none",
        "policy_digest": _DIGEST_B,
    }
    manifest["audit"] = {
        "report": _artifact("mcp-audit-report", _DIGEST_B),
        "report_schema_version": 1,
        "detector_ids": ["permissions", "injection", "ssrf"],
        "connection_statuses": {"safeforge-echo": "connected"},
        "warning_codes": [],
    }
    manifest["policies"] = [
        {
            "kind": "audit",
            "policy_id": "mcp-audit-research",
            "policy_version": "1",
            "policy_digest": _DIGEST_A,
            "result": "passed",
        },
        {
            "kind": "egress",
            "policy_id": "egress-test-policy",
            "policy_version": "1",
            "policy_digest": _DIGEST_B,
            "result": "passed",
        },
    ]
    manifest["grade"] = {
        "grade": "A",
        "transparency": "high",
        "audit_report_digest": _DIGEST_B,
        "grading_policy_version": "1",
        "current": True,
    }
    manifest["publication"] = {
        "target": "official-mcp-registry",
        "metadata_digest": _DIGEST_C,
        "schema_version": "2025-12-11",
        "result": "passed",
        "dry_run": True,
    }
    manifest["integrity"] = {
        "hash_algorithm": "sha256",
        "receipt_refs": [_artifact("final-receipt", _DIGEST_C)],
        "signature_refs": [],
    }
    return manifest


def _codes(payload: dict[str, object], *, require_final: bool = False) -> set[str]:
    result = validate_safeforge_manifest(payload, require_final=require_final)
    return {finding.code for finding in result.findings}


def test_incremental_manifest_is_valid_without_finalization() -> None:
    result = validate_safeforge_manifest(_base_manifest())
    assert result.valid
    assert result.findings == []
    assert result.manifest is not None


def test_research_stage_order_places_static_validation_before_preinstall() -> None:
    assert RESEARCH_MVP_STAGE_ORDER.index(StageId.VALIDATE_STATIC) < RESEARCH_MVP_STAGE_ORDER.index(
        StageId.CONTRACT_PREINSTALL
    )


def test_complete_research_manifest_is_eligible() -> None:
    result = validate_safeforge_manifest(_final_manifest(), require_final=True)
    assert result.valid
    assert result.findings == []


def test_generated_json_schema_matches_committed_contract() -> None:
    expected = json.loads(Path("examples/schemas/safeforge-manifest-v0.schema.json").read_text())
    assert expected == safeforge_manifest_json_schema()


def test_observed_network_requires_matching_declaration() -> None:
    payload = _base_manifest()
    payload["toolbom"][0]["observed_capabilities"] = ["network"]
    result = validate_safeforge_manifest(payload)
    assert not result.valid
    assert {finding.code for finding in result.findings} == {"SF-CONTRACT-EGRESS-DYNAMIC"}


def test_observed_filesystem_requires_matching_permission() -> None:
    payload = _base_manifest()
    payload["toolbom"][0]["observed_capabilities"] = ["filesystem"]
    result = validate_safeforge_manifest(payload)
    assert not result.valid
    assert {finding.code for finding in result.findings} == {"SF-CONTRACT-FILESYSTEM-UNDECLARED"}


def test_schema_forbids_secret_bearing_extra_fields() -> None:
    manifest = _base_manifest()
    manifest["api_token"] = "should-never-be-accepted"
    assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_digest_format_is_fail_closed() -> None:
    manifest = _base_manifest()
    manifest["artifact"]["tree_digest"] = "not-a-digest"
    assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_artifact_uri_must_be_portable() -> None:
    manifest = _base_manifest()
    manifest["artifact"]["files"][0]["uri"] = "/Users/private/server.py"
    assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_artifact_uri_rejects_remote_and_windows_absolute_references() -> None:
    for uri in ("https://example.invalid/evidence.json", "C:\\private\\evidence.json"):
        manifest = _base_manifest()
        manifest["artifact"]["files"][0]["uri"] = uri
        assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_negotiated_protocol_must_be_supported() -> None:
    manifest = _base_manifest()
    manifest["subject"]["mcp_protocol_negotiated"] = "2024-11-05"
    assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_tool_id_must_bind_server_and_name() -> None:
    manifest = _base_manifest()
    manifest["toolbom"][0]["tool_id"] = "other-server#echo"
    assert "SF-CONTRACT-TOOL-ID" in _codes(manifest)


def test_duplicate_tool_ids_are_rejected() -> None:
    manifest = _base_manifest()
    manifest["toolbom"].append(copy.deepcopy(manifest["toolbom"][0]))
    assert "SF-CONTRACT-TOOL-DUPLICATE" in _codes(manifest)


def test_required_stage_cannot_be_skipped() -> None:
    manifest = _base_manifest()
    manifest["stages"] = [_stage(StageId.SOURCE_BIND, state="skipped")]
    assert "SF-CONTRACT-REQUIRED-SKIPPED" in _codes(manifest)


def test_failed_stage_requires_failure_code() -> None:
    manifest = _base_manifest()
    failed = _stage(StageId.SOURCE_BIND, state="failed")
    failed["failure_codes"] = []
    manifest["stages"] = [failed]
    assert _codes(manifest) == {"SF-CONTRACT-SCHEMA"}


def test_duplicate_attempt_number_is_rejected() -> None:
    manifest = _base_manifest()
    manifest["stages"] = [
        _stage(StageId.SOURCE_BIND, state="failed"),
        _stage(StageId.SOURCE_BIND, state="passed"),
    ]
    assert "SF-CONTRACT-ATTEMPT-DUPLICATE" in _codes(manifest)


def test_illegal_passed_to_failed_transition_is_rejected() -> None:
    manifest = _base_manifest()
    manifest["stages"] = [
        _stage(StageId.SOURCE_BIND, state="passed"),
        _stage(StageId.SOURCE_BIND, attempt=2, state="failed"),
    ]
    assert "SF-CONTRACT-STATE-TRANSITION" in _codes(manifest)


def test_stage_cannot_run_before_predecessors_pass() -> None:
    manifest = _base_manifest()
    manifest["stages"] = [
        _stage(StageId.SOURCE_BIND, state="failed"),
        _stage(StageId.FORGE_PLAN, state="passed"),
    ]
    assert "SF-CONTRACT-STAGE-ORDER" in _codes(manifest)


def test_finalization_requires_every_stage_and_evidence_section() -> None:
    codes = _codes(_base_manifest(), require_final=True)
    assert "SF-CONTRACT-STAGE-MISSING" in codes
    assert "SF-CONTRACT-EVIDENCE-MISSING" in codes
    assert "SF-CONTRACT-DECISION" in codes


def test_stale_grade_blocks_finalization() -> None:
    manifest = _final_manifest()
    manifest["grade"]["current"] = False  # type: ignore[index]
    assert "SF-TRUST-STALE" in _codes(manifest, require_final=True)


def test_grade_must_bind_exact_audit_report() -> None:
    manifest = _final_manifest()
    manifest["grade"]["audit_report_digest"] = _DIGEST_C  # type: ignore[index]
    assert "SF-TRUST-AUDIT-BINDING" in _codes(manifest, require_final=True)


def test_failed_connection_or_warning_blocks_finalization() -> None:
    manifest = _final_manifest()
    manifest["audit"]["connection_statuses"] = {"safeforge-echo": "failed"}  # type: ignore[index]
    manifest["audit"]["warning_codes"] = ["missing_detector"]  # type: ignore[index]
    codes = _codes(manifest, require_final=True)
    assert {"SF-AUDIT-CONNECTION", "SF-AUDIT-COVERAGE"} <= codes


def test_final_manifest_requires_audit_and_egress_policy_roles() -> None:
    manifest = _final_manifest()
    manifest["policies"] = [manifest["policies"][0]]  # type: ignore[index]
    assert "SF-POLICY-COVERAGE" in _codes(manifest, require_final=True)


def test_final_sandbox_must_be_network_off_and_credential_free() -> None:
    manifest = _final_manifest()
    manifest["sandbox"]["network"] = "host"  # type: ignore[index]
    manifest["sandbox"]["credential_mode"] = "dummy"  # type: ignore[index]
    codes = _codes(manifest, require_final=True)
    assert {"SF-SANDBOX-ISOLATION", "SF-SANDBOX-CREDENTIALS"} <= codes


def test_model_round_trip_preserves_contract_shape() -> None:
    model = SafeForgeManifest.model_validate(_final_manifest())
    restored = SafeForgeManifest.model_validate(model.model_dump(mode="json"))
    assert restored == model
