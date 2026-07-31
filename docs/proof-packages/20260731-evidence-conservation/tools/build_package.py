from __future__ import annotations

import argparse
import base64
import copy
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from package_lib import (
    candidate_record,
    canonical_json_bytes,
    equalize_fixture_lengths,
    extract_approved_spec,
    read_json,
    record_content_sha256,
    semantic_diff_paths,
    sha256_bytes,
    sha256_file,
    write_json,
)

SPEC_SHA256 = "711b5c32b053a0e471b9d7e8b0327160d205a8bdfa88f207a921909905afd188"
GENERATED_AT = "2026-07-31T16:20:00Z"
APPROVAL_MESSAGE_SHA256 = "7a54d1adbc69cb4f938954ea48d0c853df5da48267ef2d4d970fbce951d35548"
APPROVAL_THREAD_ID = "019fb6d5-1875-7551-ad41-f8e5258107e4"
APPROVAL_TURN_ID = "019fb6d5-1b1b-7f22-be1b-513456df2635"

CASE_TO_FIXTURE = {
    "P1-C": "fx-11",
    "P1-01": "fx-03",
    "P1-02": "fx-18",
    "P1-03": "fx-07",
    "P1-04": "fx-15",
    "P1-05": "fx-01",
    "P1-06": "fx-20",
    "P2-C": "fx-06",
    "P2-01": "fx-13",
    "P2-02": "fx-02",
    "P2-03": "fx-19",
    "P2-04": "fx-09",
    "P2-05": "fx-16",
    "P2-06": "fx-04",
    "P3-C": "fx-14",
    "P3-01": "fx-08",
    "P3-02": "fx-21",
    "P3-03": "fx-05",
    "P3-04": "fx-17",
    "P3-05": "fx-10",
    "P3-06": "fx-12",
}

AXES = {
    "01": ("MISSING", [0, 1, 1, 1, 1, 1]),
    "02": ("STALE", [1, 0, 1, 1, 1, 1]),
    "03": ("MASKED", [1, 1, 0, 1, 1, 1]),
    "04": ("CONTRADICTORY", [1, 1, 1, 0, 1, 1]),
    "05": ("UNSUPPORTED", [1, 1, 1, 1, 0, 1]),
    "06": ("MISBOUND", [1, 1, 1, 1, 1, 0]),
}

CEILINGS = {
    "P1": {
        "01": ("NONAUTHORITATIVE", "MISSING"),
        "02": ("NONAUTHORITATIVE", "STALE"),
        "03": ("NONAUTHORITATIVE", "MASKED"),
        "04": ("NONAUTHORITATIVE", "CONTRADICTORY"),
        "05": ("NONAUTHORITATIVE", "UNSUPPORTED"),
        "06": ("NONAUTHORITATIVE", "MISBOUND"),
    },
    "P2": {
        "01": ("NONAUTHORITATIVE", "MISSING"),
        "02": ("NONAUTHORITATIVE", "STALE"),
        "03": ("NONAUTHORITATIVE", "MASKED"),
        "04": ("BLOCKED", "CONTRADICTORY"),
        "05": ("BLOCKED", "UNSUPPORTED"),
        "06": ("BLOCKED", "MISBOUND"),
    },
    "P3": {
        "01": ("NONAUTHORITATIVE", "MISSING"),
        "02": ("NONAUTHORITATIVE", "STALE"),
        "03": ("BLOCKED", "MASKED"),
        "04": ("BLOCKED", "CONTRADICTORY"),
        "05": ("BLOCKED", "UNSUPPORTED"),
        "06": ("NONAUTHORITATIVE", "MISBOUND"),
    },
}

COVERAGE = {
    "P1-C": (
        "COVERED",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_successful_empty_provider_response_is_explicit_completed_zero"
        ],
    ),
    "P1-01": (
        "COVERED",
        [
            "GithubRepoAuditor:tests/test_portfolio_truth.py::test_receipt_partial_provider_coverage_emits_explicit_denominators"
        ],
    ),
    "P1-02": (
        "COVERED",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_stale_provider_observation_becomes_unknown_count"
        ],
    ),
    "P1-03": (
        "PARTIAL",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_malformed_provider_payload_has_exact_fail_closed_reason_code"
        ],
    ),
    "P1-04": (
        "PARTIAL",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_total_request_ceiling_halts_incomplete_pagination"
        ],
    ),
    "P1-05": (
        "COVERED",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_receipt_provenance_and_provider_timestamps_fail_closed"
        ],
    ),
    "P1-06": (
        "CROSS_CONTRACT",
        [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_receipt_producer_must_match_expected_canonical_commit",
            "PortfolioCommandCenter:src/validation.test.ts",
        ],
    ),
    "P2-C": (
        "COVERED",
        [
            "mcp-trust:tests/test_refresh_candidate.py::test_deterministic_fixture_candidate_is_immutable_and_reviewable"
        ],
    ),
    "P2-01": (
        "COVERED",
        ["mcp-trust:tests/test_refresh_candidate.py::test_missing_receipt_is_explicit_and_not_fresh"],
    ),
    "P2-02": ("COVERED", ["mcp-trust:tests/test_refresh_candidate.py::test_exact_expiry_boundary_is_stale"]),
    "P2-03": (
        "COVERED",
        [
            "mcp-trust:tests/test_refresh_candidate.py::test_masked_grade_is_withheld_from_results_and_snapshot"
        ],
    ),
    "P2-04": ("COVERED", ["mcp-trust:tests/test_refresh_candidate.py"]),
    "P2-05": ("PARTIAL", ["mcp-trust:src/mcp_trust/refresh.py"]),
    "P2-06": ("PARTIAL", ["mcp-trust:tests/test_receipt_provenance.py"]),
    "P3-C": (
        "COVERED",
        ["bridge-db:tests/test_recovery.py::test_create_anchor_is_private_and_disposable_recovery_verifies"],
    ),
    "P3-01": ("COVERED", ["bridge-db:tests/test_cli.py::test_recovery_anchor_cli_fails_closed_when_missing"]),
    "P3-02": (
        "COVERED",
        ["bridge-db:tests/test_recovery.py::test_anchor_inventory_becomes_stale_after_same_count_update"],
    ),
    "P3-03": ("PARTIAL", ["bridge-db:tests/test_recovery.py::test_anchor_detects_manifest_digest_mismatch"]),
    "P3-04": ("PARTIAL", ["bridge-db:tests/test_recovery.py::test_anchor_detects_backup_tampering"]),
    "P3-05": (
        "COVERED",
        [
            "bridge-db:tests/test_recovery.py::test_anchor_detects_incompatible_schema_even_with_rebound_digest"
        ],
    ),
    "P3-06": (
        "PARTIAL",
        ["bridge-db:tests/test_recovery.py::test_anchor_inventory_becomes_stale_after_source_insert"],
    ),
}


def _object(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required if required is not None else list(properties),
    }


def _array(
    items: dict[str, Any], *, minimum: int | None = None, maximum: int | None = None
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "array", "items": items}
    if minimum is not None:
        schema["minItems"] = minimum
    if maximum is not None:
        schema["maxItems"] = maximum
    return schema


STRING = {"type": "string", "minLength": 1}
SHA256 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
UTC_OR_NULL = {"type": ["string", "null"]}
OPEN_OBJECT = {"type": "object"}


def _record_schema(schema_name: str, body: dict[str, Any]) -> dict[str, Any]:
    review = _object(
        {
            "reviewer_id": STRING,
            "independent_from": _array(STRING),
            "decision": {"enum": ["ADMIT", "REJECT"]},
            "reviewed_at_utc": STRING,
            "reviewed_content_sha256": SHA256,
            "rationale": STRING,
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:mcpaudit:evidence-conservation:{schema_name}",
        **_object(
            {
                "schema": {"const": schema_name},
                "record_id": STRING,
                "spec_sha256": SHA256,
                "created_at_utc": STRING,
                "producer": _object({"actor_id": STRING, "role": STRING}),
                "supersedes": {"type": ["string", "null"]},
                "body": body,
                "content_sha256": SHA256,
                "reviews": _array(review),
                "admission_status": {"enum": ["CANDIDATE", "ADMITTED", "REJECTED"]},
            }
        ),
    }


def build_schemas() -> dict[str, dict[str, Any]]:
    boundary_body = _object(
        {
            "strict_downgrade": {"const": "REQUIRED"},
            "pcc_binding_owner": {"const": "PORTFOLIO_COMMAND_CENTER"},
            "p2_decision_surface": {"const": "PER_SERVER_FIXTURE_GRADE_ADMISSIBILITY"},
            "p2_exclusions": _array(STRING, minimum=4, maximum=4),
            "approval_evidence": _object({"thread_id": STRING, "turn_id": STRING, "message_sha256": SHA256}),
            "contradictions": _array(OPEN_OBJECT, maximum=0),
        }
    )
    digest_item = _object({"path": STRING, "sha256": SHA256})
    formatted_digest_item = _object({"path": STRING, "sha256": SHA256, "format": STRING})
    component = _object(
        {
            "role": {"enum": ["PRODUCER", "CONSUMER"]},
            "repository": STRING,
            "revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "contract_ids": _array(STRING, minimum=1),
            "source_files": _array(digest_item, minimum=1),
            "manifests": _array(formatted_digest_item, minimum=1),
            "locks": _array(formatted_digest_item, minimum=1),
            "runtime_declarations": _array(
                _object({"path": STRING, "sha256": SHA256, "constraint": STRING}),
                minimum=1,
            ),
        }
    )
    artifact = _object({"name": STRING, "version": STRING, "kind": STRING, "sha256": SHA256})
    resolved_environment = _object(
        {
            "os": STRING,
            "architecture": STRING,
            "runtime_versions": OPEN_OBJECT,
            "package_manager_versions": OPEN_OBJECT,
            "sqlite_version": STRING,
            "filesystem_semantics": OPEN_OBJECT,
        }
    )
    freeze_body = _object(
        {
            "path_id": {"enum": ["P1", "P2", "P3"]},
            "components": _array(component, minimum=1),
            "artifacts": _array(artifact),
            "resolved_environment": resolved_environment,
            "lock_consistency": _object(
                {"status": {"enum": ["VERIFIED", "FAILED"]}, "verifier": STRING, "receipt_sha256": SHA256}
            ),
            "clock_contract": STRING,
            "all_objects_resolve": {"type": "boolean"},
        }
    )
    authority = _object(
        {
            "authority": {"enum": ["BLOCKED", "NONAUTHORITATIVE", "CONDITIONAL", "STRONG"]},
            "disposition": {
                "enum": [
                    "VALID",
                    "PARTIAL",
                    "MISSING",
                    "STALE",
                    "MASKED",
                    "CONTRADICTORY",
                    "UNSUPPORTED",
                    "MISBOUND",
                ]
            },
        }
    )
    oracle_entry = _object(
        {
            "case_id": {"type": "string", "pattern": "^P[123]-(?:C|0[1-6])$"},
            "path_id": {"enum": ["P1", "P2", "P3"]},
            "control_case_id": {"type": "string", "pattern": "^P[123]-C$"},
            "evidence_vector": _array({"enum": [0, 1]}, minimum=6, maximum=6),
            "evidence_relation": {"enum": ["CONTROL", "STRICTLY_BELOW_CONTROL"]},
            "authority_ceiling": authority,
            "disposition": authority["properties"]["disposition"],
            "accepted_reason_families": _array(STRING, minimum=1),
            "claim_critical": {"type": "boolean"},
            "rationale": STRING,
            "contract_refs": _array(STRING, minimum=1),
        }
    )
    pending_reviewer = _object(
        {
            "reviewer_id": STRING,
            "status": {"const": "PENDING_INDEPENDENT_REVIEW"},
        }
    )
    oracle_body = _object(
        {
            "oracle_id": STRING,
            "freeze_receipt_ids": _array(STRING, minimum=3, maximum=3),
            "entries": _array(oracle_entry, minimum=21, maximum=21),
            "reviewers": _array(pending_reviewer, minimum=2, maximum=2),
            "blindness_attestations": _array(pending_reviewer, minimum=2, maximum=2),
            "agreement": _object(
                {
                    "method": {"const": "COHENS_KAPPA"},
                    "initial_value": {"type": ["number", "null"]},
                    "initial_disagreements": _array(OPEN_OBJECT),
                }
            ),
            "adjudicator": {"type": ["object", "null"]},
            "final_agreement_count": {"type": "integer", "minimum": 0, "maximum": 21},
            "consumer_outputs_seen": {"const": False},
            "sealed_at_utc": UTC_OR_NULL,
            "oracle_sha256": SHA256,
        }
    )
    fixture_artifact = _object(
        {
            "ref": STRING,
            "media_type": {"const": "application/json"},
            "bytes": {"type": "integer", "minimum": 1},
            "sha256": SHA256,
        }
    )
    vector = _array({"enum": [0, 1]}, minimum=6, maximum=6)
    fixture_body = _object(
        {
            "case_id": STRING,
            "path_id": {"enum": ["P1", "P2", "P3"]},
            "family_id": STRING,
            "control_case_id": STRING,
            "fixture_kind": {"enum": ["CONTROL", "MUTATION"]},
            "artifacts": _array(fixture_artifact, minimum=1),
            "generator": _object({"repository": STRING, "revision": STRING, "config_sha256": SHA256}),
            "provenance": _object(
                {
                    "source_class": {"const": "SYNTHETIC_FROM_FIRST_PRINCIPLES"},
                    "source_ref": STRING,
                    "license": {"const": "CC0-1.0"},
                    "derivation": STRING,
                }
            ),
            "rights": _object(
                {
                    "classification": {"const": "PROJECT_GENERATED_SYNTHETIC"},
                    "reviewer": {"const": "PENDING_INDEPENDENT_REVIEW"},
                    "admissible": {"const": True},
                }
            ),
            "privacy": _object(
                {
                    "synthetic_only": {"const": True},
                    "reserved_identities_only": {"const": True},
                    "real_data_present": {"const": False},
                }
            ),
            "secret_scan": _object(
                {
                    "scanner": {"const": "EvidencePackageSecretScanV1"},
                    "ruleset_sha256": SHA256,
                    "findings": {"const": 0},
                    "allowlist": _array(STRING, maximum=0),
                }
            ),
            "mutation_locality": _object(
                {
                    "axis": {
                        "enum": [
                            "CONTROL",
                            "MISSING",
                            "STALE",
                            "MASKED",
                            "CONTRADICTORY",
                            "UNSUPPORTED",
                            "MISBOUND",
                        ]
                    },
                    "parent_sha256": SHA256,
                    "changed_fields": _array(STRING),
                    "before_vector": vector,
                    "after_vector": vector,
                    "favourability_payload_unchanged": {"type": "boolean"},
                }
            ),
            "contamination": _object(
                {
                    "opaque_names": {"const": True},
                    "oracle_fields_visible": {"const": False},
                    "mutation_label_visible": {"const": False},
                }
            ),
        }
    )
    profile = _object(
        {
            "profile_id": STRING,
            "os": STRING,
            "architecture": STRING,
            "runtimes": OPEN_OBJECT,
            "package_managers": OPEN_OBJECT,
            "sqlite_version": STRING,
            "timezone": {"const": "UTC"},
            "locale": {"const": "C"},
            "encoding": {"const": "UTF-8"},
            "fixed_clock": STRING,
            "random_seed": {"type": "integer"},
            "python_hash_seed": {"type": "integer"},
            "environment_allowlist": _array(STRING),
            "filesystem_semantics": OPEN_OBJECT,
            "network_denial": STRING,
            "subprocess_policy": STRING,
            "writable_roots": _array(STRING),
            "canonicalization_exclusions": _array(STRING),
            "repeat_count": {"const": 10},
        }
    )
    preflight_result = _object(
        {"profile_id": STRING, "status": STRING, "reason": STRING},
        required=["profile_id", "status"],
    )
    determinism_body = _object(
        {
            "profiles": _array(profile, minimum=2, maximum=2),
            "freeze_receipt_ids": _array(STRING, minimum=3, maximum=3),
            "preflight_results": _array(preflight_result, minimum=2, maximum=2),
            "profile_sha256": SHA256,
        }
    )
    coverage_entry = _object(
        {
            "case_id": {"type": "string", "pattern": "^P[123]-(?:C|0[1-6])$"},
            "classification": {"enum": ["COVERED", "PARTIAL", "CROSS_CONTRACT"]},
            "source_tests": _array(STRING, minimum=1),
            "asserted_surface": STRING,
            "missing_assertion": STRING,
            "cross_contract_delta": STRING,
            "reviewer_rationale": {"const": "PENDING_INDEPENDENT_REVIEW"},
        }
    )
    coverage_body = _object(
        {
            "freeze_receipt_ids": _array(STRING, minimum=3, maximum=3),
            "entries": _array(coverage_entry, minimum=21, maximum=21),
            "primary_counts": _object(
                {
                    "covered": {"type": "integer"},
                    "partial": {"type": "integer"},
                    "cross_contract": {"type": "integer"},
                }
            ),
            "unmapped_count": {"const": 0},
            "new_claim": STRING,
            "coverage_sha256": SHA256,
        }
    )
    ownership_body = _object(
        {
            "observed_at_utc": STRING,
            "fresh_for_seconds": {"type": "integer", "minimum": 1},
            "target": _object(
                {
                    "repository": STRING,
                    "worktree": STRING,
                    "branch": STRING,
                    "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                    "base_ref": STRING,
                }
            ),
            "git_state": _object(
                {
                    "tracked_changes": _array(STRING),
                    "untracked_changes": _array(STRING),
                    "preserved_paths": _array(STRING),
                }
            ),
            "lease": _object(
                {
                    "state": {"enum": ["HELD", "AVAILABLE", "CONFLICT"]},
                    "owner": STRING,
                    "expires_at_utc": UTC_OR_NULL,
                }
            ),
            "peer_preflight": _object(
                {"checker": STRING, "receipt_sha256": SHA256, "result": {"const": "CLAIM"}}
            ),
            "allowed_writes": _array(STRING, minimum=1),
            "forbidden_effects": _array(STRING, minimum=1),
            "publication": _object({"allowed": {"const": False}, "remote_effects": {"const": False}}),
        }
    )
    common = _record_schema("CommonRecordEnvelopeV1", OPEN_OBJECT)
    primary_fixture = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "PrimaryFixtureV1"},
                "opaque_fixture_id": {"pattern": "^fx-[0-9]{2}$", "type": "string"},
                "path_contract": {
                    "enum": [
                        "P1ConsumerInputV1",
                        "MCPTrustPerServerFixtureAdmissibilityV1",
                        "BridgeRecoveryReadinessFixtureV1",
                    ]
                },
                "payload": OPEN_OBJECT,
                "padding": {"type": "string", "pattern": "^0*$"},
            }
        ),
    }
    p1_provider = _object(
        {
            "alert_count": {
                "oneOf": [
                    {"type": "integer", "minimum": 0},
                    {"const": "REDACTED"},
                ]
            },
            "observed_at": STRING,
            "pagination_complete": {"type": "boolean"},
        }
    )
    p1_providers = _object(
        {
            "code_scanning": p1_provider,
            "dependabot": p1_provider,
            "secret_scanning": p1_provider,
        },
        required=["code_scanning", "dependabot"],
    )
    p1_repository_entry = _object({"providers": p1_providers})
    p1_producer = _object(
        {
            "repository": {"const": "https://code.example.invalid/auditor.git"},
            "commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
        }
    )
    p1_receipt = _object(
        {
            "schema": {"enum": ["GitHubSecurityCoverageReceiptV1", "GitHubSecurityCoverageReceiptV2"]},
            "producer": p1_producer,
            "produced_at": STRING,
            "repositories": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 1,
                "propertyNames": {"pattern": "^code\\.example\\.invalid/[a-z0-9-]+/[a-z0-9-]+$"},
                "additionalProperties": p1_repository_entry,
            },
        }
    )
    p1_snapshot_security = _object(
        {
            "receipt_schema": {
                "enum": ["GitHubSecurityCoverageReceiptV1", "GitHubSecurityCoverageReceiptV2"]
            },
            "receipt_state": {"enum": ["fresh", "stale"]},
            "coverage_state": {"enum": ["complete", "incomplete", "stale"]},
            "providers": p1_providers,
        }
    )
    p1_project = _object(
        {
            "identity": _object(
                {
                    "repo_full_name": {
                        "type": "string",
                        "pattern": "^code\\.example\\.invalid/[a-z0-9-]+/[a-z0-9-]+$",
                    }
                }
            ),
            "security": p1_snapshot_security,
        }
    )
    p1_payload = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "P1ConsumerInputV1"},
                "fixed_clock": STRING,
                "receipt": p1_receipt,
                "snapshot": _object(
                    {
                        "schema": {"const": "PortfolioTruthV0.11.0"},
                        "producer": p1_producer,
                        "projects": _array(p1_project, minimum=1, maximum=1),
                    }
                ),
            }
        ),
    }
    grade = {"enum": ["A", "B", "C", "D", "E", "F"]}
    p2_engine_result = _object(
        {
            "grade": grade,
            "risk_score": {"type": "number", "minimum": 0},
            "findings": _array(STRING),
        }
    )
    p2_receipt = _object(
        {
            "format_version": {"enum": [1, 2]},
            "server_slug": {
                "type": "string",
                "pattern": "^[a-z0-9-]+\\.example\\.invalid$",
            },
            "scan_id": STRING,
            "fresh_grade": grade,
        }
    )
    p2_server_scan = _object(
        {
            "server_slug": {
                "type": "string",
                "pattern": "^[a-z0-9-]+\\.example\\.invalid$",
            },
            "scan_id": STRING,
            "grade": grade,
        }
    )
    p2_payload = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "MCPTrustPerServerFixtureAdmissibilityV1"},
                "fixed_clock": STRING,
                "expires_at": STRING,
                "candidate": _object(
                    {
                        "structural_valid": {"type": "boolean"},
                        "publication_ready": {"const": False},
                        "server_slug": {
                            "type": "string",
                            "pattern": "^[a-z0-9-]+\\.example\\.invalid$",
                        },
                        "scan_id": {"type": ["string", "null"]},
                        "engine_result": p2_engine_result,
                        "artifact_sha256": SHA256,
                        "candidate_manifest_sha256": SHA256,
                        "receipt": {"oneOf": [p2_receipt, {"type": "null"}]},
                        "receipt_sha256": {"oneOf": [SHA256, {"type": "null"}]},
                        "result_state": {"enum": ["fresh", "missing", "stale", "masked"]},
                        "fresh_grade": {"oneOf": [grade, {"type": "null"}]},
                        "drift": {"oneOf": [_array(STRING), {"type": "null"}]},
                        "reviewed_masking": {"type": "boolean"},
                    }
                ),
                "persisted_scan": p2_server_scan,
                "static_snapshot": _object({"servers": _array(p2_server_scan, maximum=1)}),
            }
        ),
    }
    p3_manifest = _object(
        {
            "source_identity": {
                "type": "string",
                "pattern": "^db-[a-z0-9-]+\\.example\\.invalid$",
            },
            "source_schema_version": {"type": "integer", "minimum": 1},
            "sha256": {"oneOf": [SHA256, {"const": "REDACTED_SHA256"}]},
            "backup_bytes": {"type": "integer", "minimum": 1},
            "source_fingerprint": SHA256,
        }
    )
    p3_anchor = _object(
        {
            "database_b64": STRING,
            "database_mode": {"const": "0600"},
            "directory_mode": {"const": "0700"},
            "manifest": p3_manifest,
            "manifest_mode": {"const": "0600"},
        }
    )
    p3_payload = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "BridgeRecoveryReadinessFixtureV1"},
                "source": _object(
                    {
                        "identity": {
                            "type": "string",
                            "pattern": "^db-[a-z0-9-]+\\.example\\.invalid$",
                        },
                        "database_b64": STRING,
                        "mode": {"const": "0600"},
                    }
                ),
                "anchor": {"oneOf": [p3_anchor, {"type": "null"}]},
            }
        ),
    }
    regeneration_receipt = _object(
        {
            "schema": {"const": "DeterministicRegenerationV1"},
            "status": {"enum": ["PASS", "FAIL", "SKIPPED"]},
            "byte_identical": {"type": ["boolean", "null"]},
            "compared_files": {"type": "integer", "minimum": 0},
            "mismatches": _array(STRING),
        }
    )
    summary = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "EvidencePackageAdmissionSummaryV1"},
                "spec_sha256": SHA256,
                "generated_at_utc": STRING,
                "terminal_state": {
                    "enum": [
                        "EVIDENCE_PACKAGE_CANDIDATE_COMPLETE_REVIEW_REQUIRED",
                        "EVIDENCE_PACKAGE_ADMITTED",
                        "BLOCKED_PREFLIGHT",
                        "BLOCKED_CONTRACT",
                        "KILL_RECOMMENDED",
                    ]
                },
                "record_counts": _object(
                    {
                        "total": {"const": 29},
                        "candidate": {"const": 29},
                        "admitted": {"const": 0},
                        "pending_independent_review": {"const": 29},
                        "failed_local_admission_gate": {"type": "integer", "minimum": 0},
                    }
                ),
                "fixture_counts": _object(
                    {
                        "total": {"const": 21},
                        "controls": {"const": 3},
                        "one_axis_mutations": {"const": 18},
                    }
                ),
                "checks": _array(
                    _object({"name": STRING, "status": STRING, "detail": STRING}),
                    minimum=1,
                ),
                "deterministic_regeneration": regeneration_receipt,
                "independent_review": _object(
                    {
                        "status": {"const": "PENDING_INDEPENDENT_REVIEW"},
                        "required_records": {"const": 29},
                        "completed_records": {"const": 0},
                        "oracle_reviewers_required": {"const": 2},
                        "second_environment_required": {"const": True},
                    }
                ),
                "remote_lease": _object(
                    {
                        "branch": STRING,
                        "base_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                        "remote_tip_expected": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{40}$",
                        },
                        "further_remote_effects_authorized": {"const": False},
                    }
                ),
                "authorization_boundary": STRING,
            }
        ),
    }
    generation = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **_object(
            {
                "schema": {"const": "EvidencePackageGenerationManifestV1"},
                "spec_sha256": SHA256,
                "generated_at_utc": STRING,
                "files": _array(
                    _object(
                        {
                            "path": STRING,
                            "bytes": {"type": "integer", "minimum": 1},
                            "sha256": SHA256,
                            "role": {"const": "DETERMINISTIC_ARTIFACT"},
                        }
                    ),
                    minimum=1,
                ),
                "deterministic_artifacts": _array(STRING, minimum=1),
                "excluded_from_regeneration": _array(STRING, minimum=1),
            }
        ),
    }
    return {
        "common-record-envelope-v1.schema.json": common,
        "boundary-decision-v1.schema.json": _record_schema("BoundaryDecisionV1", boundary_body),
        "freeze-receipt-v1.schema.json": _record_schema("FreezeReceiptV1", freeze_body),
        "oracle-adjudication-v1.schema.json": _record_schema("OracleAdjudicationV1", oracle_body),
        "fixture-admissibility-v1.schema.json": _record_schema("FixtureAdmissibilityV1", fixture_body),
        "determinism-profile-v1.schema.json": _record_schema("DeterminismProfileV1", determinism_body),
        "coverage-delta-v1.schema.json": _record_schema("CoverageDeltaV1", coverage_body),
        "ownership-preflight-v1.schema.json": _record_schema("OwnershipPreflightV1", ownership_body),
        "primary-fixture-v1.schema.json": primary_fixture,
        "p1-consumer-input-v1.schema.json": p1_payload,
        "p2-fixture-admissibility-v1.schema.json": p2_payload,
        "p3-recovery-fixture-v1.schema.json": p3_payload,
        "admission-summary-v1.schema.json": summary,
        "generation-manifest-v1.schema.json": generation,
    }


def _p1_control() -> dict[str, Any]:
    subject = "code.example.invalid/example-org/project-alpha"
    provider = {"alert_count": 0, "observed_at": "2030-01-02T00:00:00Z", "pagination_complete": True}
    providers = {
        "code_scanning": copy.deepcopy(provider),
        "dependabot": copy.deepcopy(provider),
        "secret_scanning": copy.deepcopy(provider),
    }
    return {
        "schema": "P1ConsumerInputV1",
        "fixed_clock": "2030-01-02T12:00:00Z",
        "receipt": {
            "schema": "GitHubSecurityCoverageReceiptV1",
            "producer": {"repository": "https://code.example.invalid/auditor.git", "commit": "a" * 40},
            "produced_at": "2030-01-02T00:00:00Z",
            "repositories": {subject: {"providers": copy.deepcopy(providers)}},
        },
        "snapshot": {
            "schema": "PortfolioTruthV0.11.0",
            "producer": {"repository": "https://code.example.invalid/auditor.git", "commit": "a" * 40},
            "projects": [
                {
                    "identity": {"repo_full_name": subject},
                    "security": {
                        "receipt_schema": "GitHubSecurityCoverageReceiptV1",
                        "receipt_state": "fresh",
                        "coverage_state": "complete",
                        "providers": copy.deepcopy(providers),
                    },
                }
            ],
        },
    }


def _p1_fixtures() -> dict[str, dict[str, Any]]:
    control = _p1_control()
    fixtures = {"P1-C": control}
    missing = copy.deepcopy(control)
    subject = next(iter(missing["receipt"]["repositories"]))
    missing["receipt"]["repositories"][subject]["providers"].pop("secret_scanning")
    missing["snapshot"]["projects"][0]["security"]["providers"].pop("secret_scanning")
    missing["snapshot"]["projects"][0]["security"]["coverage_state"] = "incomplete"
    fixtures["P1-01"] = missing
    stale = copy.deepcopy(control)
    stale["fixed_clock"] = "2030-01-03T00:00:01Z"
    stale["snapshot"]["projects"][0]["security"]["receipt_state"] = "stale"
    stale["snapshot"]["projects"][0]["security"]["coverage_state"] = "stale"
    fixtures["P1-02"] = stale
    masked = copy.deepcopy(control)
    masked["receipt"]["repositories"][subject]["providers"]["dependabot"]["alert_count"] = "REDACTED"
    masked["snapshot"]["projects"][0]["security"]["providers"]["dependabot"]["alert_count"] = "REDACTED"
    fixtures["P1-03"] = masked
    contradictory = copy.deepcopy(control)
    contradictory["receipt"]["repositories"][subject]["providers"]["code_scanning"]["pagination_complete"] = (
        False
    )
    contradictory["snapshot"]["projects"][0]["security"]["providers"]["code_scanning"][
        "pagination_complete"
    ] = False
    fixtures["P1-04"] = contradictory
    unsupported = copy.deepcopy(control)
    unsupported["receipt"]["schema"] = "GitHubSecurityCoverageReceiptV2"
    unsupported["snapshot"]["projects"][0]["security"]["receipt_schema"] = "GitHubSecurityCoverageReceiptV2"
    fixtures["P1-05"] = unsupported
    misbound = copy.deepcopy(control)
    misbound["snapshot"]["projects"][0]["identity"]["repo_full_name"] = (
        "code.example.invalid/example-org/project-beta"
    )
    fixtures["P1-06"] = misbound
    return fixtures


def _digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _p2_control() -> dict[str, Any]:
    engine_result = {"grade": "A", "risk_score": 1.0, "findings": []}
    receipt = {
        "format_version": 1,
        "server_slug": "server-a.example.invalid",
        "scan_id": "scan-opaque-001",
        "fresh_grade": "A",
    }
    payload = {
        "schema": "MCPTrustPerServerFixtureAdmissibilityV1",
        "fixed_clock": "2030-01-02T12:00:00Z",
        "expires_at": "2030-01-03T00:00:00Z",
        "candidate": {
            "structural_valid": True,
            "publication_ready": False,
            "server_slug": "server-a.example.invalid",
            "scan_id": "scan-opaque-001",
            "engine_result": engine_result,
            "artifact_sha256": "",
            "candidate_manifest_sha256": "",
            "receipt": receipt,
            "receipt_sha256": "",
            "result_state": "fresh",
            "fresh_grade": "A",
            "drift": [],
            "reviewed_masking": False,
        },
        "persisted_scan": {
            "server_slug": "server-a.example.invalid",
            "scan_id": "scan-opaque-001",
            "grade": "A",
        },
        "static_snapshot": {
            "servers": [
                {"server_slug": "server-a.example.invalid", "scan_id": "scan-opaque-001", "grade": "A"}
            ]
        },
    }
    _bind_p2_payload(payload)
    return payload


def _bind_p2_payload(payload: dict[str, Any]) -> None:
    candidate = payload["candidate"]
    receipt = candidate["receipt"]
    candidate["artifact_sha256"] = _digest_object(
        {
            "engine_result": candidate["engine_result"],
            "fresh_grade": candidate["fresh_grade"],
        }
    )
    candidate["receipt_sha256"] = _digest_object(receipt) if receipt is not None else None
    candidate["candidate_manifest_sha256"] = _digest_object(
        {
            "artifact_sha256": candidate["artifact_sha256"],
            "expires_at": payload["expires_at"],
            "receipt_sha256": candidate["receipt_sha256"],
            "result_state": candidate["result_state"],
            "scan_id": candidate["scan_id"],
            "server_slug": candidate["server_slug"],
        }
    )


def _p2_fixtures() -> dict[str, dict[str, Any]]:
    control = _p2_control()
    fixtures = {"P2-C": control}
    missing = copy.deepcopy(control)
    missing["candidate"]["receipt"] = None
    missing["candidate"]["receipt_sha256"] = None
    missing["candidate"]["fresh_grade"] = None
    missing["candidate"]["result_state"] = "missing"
    _bind_p2_payload(missing)
    fixtures["P2-01"] = missing
    stale = copy.deepcopy(control)
    stale["fixed_clock"] = stale["expires_at"]
    fixtures["P2-02"] = stale
    masked = copy.deepcopy(control)
    masked["candidate"]["reviewed_masking"] = True
    masked["candidate"]["fresh_grade"] = None
    masked["candidate"]["receipt"] = None
    masked["candidate"]["receipt_sha256"] = None
    masked["candidate"]["scan_id"] = None
    masked["candidate"]["drift"] = None
    masked["candidate"]["result_state"] = "masked"
    masked["static_snapshot"]["servers"] = []
    _bind_p2_payload(masked)
    fixtures["P2-03"] = masked
    contradictory = copy.deepcopy(control)
    contradictory["candidate"]["fresh_grade"] = "F"
    _bind_p2_payload(contradictory)
    fixtures["P2-04"] = contradictory
    unsupported = copy.deepcopy(control)
    unsupported["candidate"]["receipt"]["format_version"] = 2
    _bind_p2_payload(unsupported)
    fixtures["P2-05"] = unsupported
    misbound = copy.deepcopy(control)
    misbound["candidate"]["receipt"]["scan_id"] = "scan-opaque-002"
    _bind_p2_payload(misbound)
    fixtures["P2-06"] = misbound
    return fixtures


def _sqlite_bytes(rows: list[tuple[str, str]], schema_version: int) -> bytes:
    with tempfile.TemporaryDirectory(prefix="evidence-conservation-sqlite-") as temporary:
        path = Path(temporary) / "fixture.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA page_size=4096")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute(f"PRAGMA user_version={schema_version}")
        connection.execute("CREATE TABLE facts (id TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID")
        connection.executemany("INSERT INTO facts(id, value) VALUES (?, ?)", sorted(rows))
        connection.commit()
        connection.execute("VACUUM")
        connection.close()
        return path.read_bytes()


def _p3_payload(
    *,
    source_identity: str,
    source_rows: list[tuple[str, str]],
    anchor_identity: str,
    anchor_rows: list[tuple[str, str]],
    schema_version: int = 22,
) -> dict[str, Any]:
    source_bytes = _sqlite_bytes(source_rows, schema_version)
    anchor_bytes = _sqlite_bytes(anchor_rows, schema_version)
    fingerprint = _digest_object({"source_identity": anchor_identity, "rows": sorted(anchor_rows)})
    manifest = {
        "source_identity": anchor_identity,
        "source_schema_version": schema_version,
        "sha256": sha256_bytes(anchor_bytes),
        "backup_bytes": len(anchor_bytes),
        "source_fingerprint": fingerprint,
    }
    return {
        "schema": "BridgeRecoveryReadinessFixtureV1",
        "source": {
            "identity": source_identity,
            "database_b64": base64.b64encode(source_bytes).decode("ascii"),
            "mode": "0600",
        },
        "anchor": {
            "database_b64": base64.b64encode(anchor_bytes).decode("ascii"),
            "database_mode": "0600",
            "directory_mode": "0700",
            "manifest": manifest,
            "manifest_mode": "0600",
        },
    }


def _p3_fixtures() -> dict[str, dict[str, Any]]:
    rows_a = [("fact-001", "alpha"), ("fact-002", "beta")]
    rows_b = [("fact-001", "alpha"), ("fact-002", "gamma")]
    control = _p3_payload(
        source_identity="db-a.example.invalid",
        source_rows=rows_a,
        anchor_identity="db-a.example.invalid",
        anchor_rows=rows_a,
    )
    fixtures = {"P3-C": control}
    missing = copy.deepcopy(control)
    missing["anchor"] = None
    fixtures["P3-01"] = missing
    stale = _p3_payload(
        source_identity="db-a.example.invalid",
        source_rows=[("fact-001", "alpha"), ("fact-002", "updated")],
        anchor_identity="db-a.example.invalid",
        anchor_rows=rows_a,
    )
    fixtures["P3-02"] = stale
    masked = copy.deepcopy(control)
    masked["anchor"]["manifest"]["sha256"] = "REDACTED_SHA256"
    fixtures["P3-03"] = masked
    contradictory = copy.deepcopy(control)
    contradictory["anchor"]["manifest"]["backup_bytes"] += 1
    fixtures["P3-04"] = contradictory
    fixtures["P3-05"] = _p3_payload(
        source_identity="db-a.example.invalid",
        source_rows=rows_a,
        anchor_identity="db-a.example.invalid",
        anchor_rows=rows_a,
        schema_version=23,
    )
    fixtures["P3-06"] = _p3_payload(
        source_identity="db-a.example.invalid",
        source_rows=rows_a,
        anchor_identity="db-b.example.invalid",
        anchor_rows=rows_b,
    )
    return fixtures


def build_fixtures() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    cases = {**_p1_fixtures(), **_p2_fixtures(), **_p3_fixtures()}
    fixtures: dict[str, dict[str, Any]] = {}
    for case_id, payload in cases.items():
        fixture_id = CASE_TO_FIXTURE[case_id]
        if case_id.startswith("P1"):
            contract = "P1ConsumerInputV1"
        elif case_id.startswith("P2"):
            contract = "MCPTrustPerServerFixtureAdmissibilityV1"
        else:
            contract = "BridgeRecoveryReadinessFixtureV1"
        fixtures[fixture_id] = {
            "schema": "PrimaryFixtureV1",
            "opaque_fixture_id": fixture_id,
            "path_contract": contract,
            "payload": payload,
        }
    equalize_fixture_lengths(fixtures)
    return cases, fixtures


def frozen_components() -> dict[str, Any]:
    return {
        "P1": [
            {
                "role": "PRODUCER",
                "repository": "GithubRepoAuditor",
                "revision": "fd61f1c06643c4431460e27aa9210ff8b931ef1d",
                "contract_ids": ["GitHubSecurityCoverageReceiptV1", "PortfolioTruth@0.11.0"],
                "source_files": [
                    {
                        "path": "src/github_security_coverage.py",
                        "sha256": "84c72d8bfb2a65f62a4f4504cd4ca7a0b41b6d9e888801ef82f279382b448b39",
                    },
                    {
                        "path": "src/portfolio_truth_reconcile.py",
                        "sha256": "26ac220f5440091cb2a5f387969874d3feb2a2a2bbaebd2a4bb631bae0f0a71c",
                    },
                    {
                        "path": "src/portfolio_truth_types.py",
                        "sha256": "b99383bc7eaf7e056979fc91bd23f0f087f5664582ec3b7772c68803e9fe0e2e",
                    },
                ],
                "manifests": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "f3cdf5c34df5be4b3b8d6ea52facb9cff76ee20708af3cffc4d69c20bf0a0b9c",
                        "format": "TOML",
                    },
                    {
                        "path": "requirements.txt",
                        "sha256": "22cc6c4cd15e7bd0702d18f1484930f6f216342faac1b58ab2c41efad42c9337",
                        "format": "PIP_REQUIREMENTS",
                    },
                ],
                "locks": [
                    {
                        "path": "uv.lock",
                        "sha256": "1b4d79dcedd731ddc0b35a01e8aa1672b0287afc6391d7aafe44223a130d21a6",
                        "format": "UV_LOCK",
                    }
                ],
                "runtime_declarations": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "f3cdf5c34df5be4b3b8d6ea52facb9cff76ee20708af3cffc4d69c20bf0a0b9c",
                        "constraint": "Python >=3.11",
                    }
                ],
            },
            {
                "role": "CONSUMER",
                "repository": "PortfolioCommandCenter",
                "revision": "1139cfb9bb1e8d005699f854df368583960e245c",
                "contract_ids": ["P1ConsumerInputV1", "RiskSecurityProjectDecision"],
                "source_files": [
                    {
                        "path": "src/types.ts",
                        "sha256": "687975d8991d1455b8bc1bd560a165afcba697fe0eee33af87d5de039f2e7798",
                    },
                    {
                        "path": "src/validation.ts",
                        "sha256": "bacd0786d8f8d95627deba816099803a17fc9eb96f1b1016696b0981c5b5832b",
                    },
                    {
                        "path": "src/views/RiskSecurity.tsx",
                        "sha256": "ca8884e2e910d5b71ff9f1cdb4ae548bdc1e5447c151136dead10c9fffd0bee1",
                    },
                ],
                "manifests": [
                    {
                        "path": "package.json",
                        "sha256": "5fe0a83aee75da01174fbb2472adc41fa4a1760cc9df07313a5946eb17969f9b",
                        "format": "NPM_PACKAGE",
                    },
                    {
                        "path": "src-tauri/Cargo.toml",
                        "sha256": "db446ccead7b0ddb524515d82486641cbc2288f9b90356075660626679a1b948",
                        "format": "CARGO_TOML",
                    },
                ],
                "locks": [
                    {
                        "path": "pnpm-lock.yaml",
                        "sha256": "ce22d21ebc110bf4d5f75858e36556c9b9e9911a9399be21c1c83eff3f4b2820",
                        "format": "PNPM_LOCK",
                    },
                    {
                        "path": "src-tauri/Cargo.lock",
                        "sha256": "c963d4103c730eddf6fe269f8b941623d1e70b7c4cc6ab9b71ac0cdf3c7b8445",
                        "format": "CARGO_LOCK",
                    },
                ],
                "runtime_declarations": [
                    {
                        "path": "package.json",
                        "sha256": "5fe0a83aee75da01174fbb2472adc41fa4a1760cc9df07313a5946eb17969f9b",
                        "constraint": "pnpm ==11.5.2; Node unpinned",
                    },
                    {
                        "path": "src-tauri/Cargo.toml",
                        "sha256": "db446ccead7b0ddb524515d82486641cbc2288f9b90356075660626679a1b948",
                        "constraint": "Rust edition 2021; toolchain unpinned",
                    },
                ],
            },
        ],
        "P2": [
            {
                "role": "PRODUCER",
                "repository": "MCPAudit",
                "revision": "9484d8bb1b059ce48f77015c4a84561675517a77",
                "contract_ids": ["mcp-audits==2.4.0", "EngineResult"],
                "source_files": [
                    {
                        "path": "src/mcp_audit/engine.py",
                        "sha256": "60c1e125b0ef711311a8daea37a5c3aecf821be4c0d20910961feb835ede9181",
                    },
                    {
                        "path": "src/mcp_audit/models.py",
                        "sha256": "356613e707e27f167f1f76cb92e0fbdd92d9383e110cd619387c28724b814a50",
                    },
                ],
                "manifests": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "11390acdc5225dd1fcde052b3e08c56eb4ef3ddab5fd81316a48c4787ef6777b",
                        "format": "TOML",
                    }
                ],
                "locks": [
                    {
                        "path": "uv.lock",
                        "sha256": "b68639c0bc8746066d8da1461d27bbbd240454beb368b6cdae9300adc2e454af",
                        "format": "UV_LOCK",
                    }
                ],
                "runtime_declarations": [
                    {
                        "path": ".python-version",
                        "sha256": "49a506dd32096b010d75205acf3430c9ae6c40351888129499e5a5e487126c93",
                        "constraint": "Python 3.11 family; project >=3.11",
                    }
                ],
            },
            {
                "role": "CONSUMER",
                "repository": "mcp-trust",
                "revision": "a30be69132802d2b24157066fa4dc125e8edfdca",
                "contract_ids": [
                    "MCPTrustPerServerFixtureAdmissibilityV1",
                    "RefreshCandidateV1",
                    "receipt-format-1",
                ],
                "source_files": [
                    {
                        "path": "src/mcp_trust/engine/base.py",
                        "sha256": "dc1e6b2fdebb0ae42628b16d6dd2f68c0718c377a3f95b6f0414b0248617c5c3",
                    },
                    {
                        "path": "src/mcp_trust/engine/mcpaudit.py",
                        "sha256": "b717493bb4e5ded3a06c16a2064ddb794ab33a71f1b7ee8a5e4ef7747bc7093a",
                    },
                    {
                        "path": "src/mcp_trust/refresh.py",
                        "sha256": "d54ed0300c99793f18019010802520392b077bd642581c2cae53460ed925cda6",
                    },
                ],
                "manifests": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "f3bac0415dbc201ddc6de73fffc207b651f8eb395674d2f9a0574c4b3e2e7c3d",
                        "format": "TOML",
                    }
                ],
                "locks": [
                    {
                        "path": "uv.lock",
                        "sha256": "2bfd0d8f432abf289644b2fdca2e17b8cd30a1937dd36d57dfdb5a313a893609",
                        "format": "UV_LOCK",
                    }
                ],
                "runtime_declarations": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "f3bac0415dbc201ddc6de73fffc207b651f8eb395674d2f9a0574c4b3e2e7c3d",
                        "constraint": "Python >=3.11; exact patch unpinned",
                    }
                ],
            },
        ],
        "P3": [
            {
                "role": "PRODUCER",
                "repository": "bridge-db",
                "revision": "b47e5428b0f512c5e4ab87212acdd1d844b365b0",
                "contract_ids": ["RecoveryAnchorV1", "source-schema-22", "BridgeRecoveryReadinessProjection"],
                "source_files": [
                    {
                        "path": "src/bridge_db/recovery.py",
                        "sha256": "4a67339663dfd4f4317c80071f1dd5d25b13f74cf49905cd766d3cf1fd22a356",
                    },
                    {
                        "path": "src/bridge_db/db.py",
                        "sha256": "96ad93104be0aedf9349ccb8b7ceb25f51cfff03c2ac39e59bc7fc2f32ae76f5",
                    },
                    {
                        "path": "src/bridge_db/tools/health.py",
                        "sha256": "565955fcb2b26515646420126e814edeeadbf2a88080fbd1c040bfbd3ee1660b",
                    },
                ],
                "manifests": [
                    {
                        "path": "pyproject.toml",
                        "sha256": "2d2d6fd5128603e2757a6952f21c06b6eb2b7493b8669e325de964f27692a595",
                        "format": "TOML",
                    }
                ],
                "locks": [
                    {
                        "path": "uv.lock",
                        "sha256": "f300fccebaa2a5e68ceb3f98ced5bb115038dd6bfc19c8f93829d64d3c8d736f",
                        "format": "UV_LOCK",
                    }
                ],
                "runtime_declarations": [
                    {
                        "path": ".python-version",
                        "sha256": "7b55f8e67b5623c4bef3fa691288da9437d79d3aba156de48d481db32ac7d16d",
                        "constraint": "Python 3.12 family; project >=3.12",
                    }
                ],
            }
        ],
    }


def verification_receipts() -> dict[str, dict[str, Any]]:
    runtime = {
        "schema": "RuntimeObservationV1",
        "observed_at_utc": "2026-07-31T16:08:00Z",
        "isolation": {
            "network": "DENIED_BY_OFFLINE_FLAGS",
            "home_and_caches": "DISPOSABLE_REDIRECT",
            "producer_consumer_repository_writes": 0,
            "evidence_package_repository_writes": "ALLOWED_MANIFEST_ONLY",
        },
        "os": "macOS 26.6; Darwin 25.6.0",
        "architecture": "arm64",
        "filesystem": "APFS",
        "runtimes": {
            "system_python": "3.14.6",
            "GithubRepoAuditor_python": "3.12.13",
            "MCPAudit_python": "3.11.15",
            "mcp-trust_python": "3.12.13",
            "bridge-db_python": "3.12.13",
            "node": "26.5.0",
            "rustc": "1.97.1",
            "sqlite_cli": "3.51.0",
            "generator_python_sqlite": sqlite3.sqlite_version,
        },
        "package_managers": {"uv": "0.12.0", "pnpm": "11.18.0", "cargo": "1.97.1"},
        "mismatches": [
            "PortfolioCommandCenter declares pnpm 11.5.2; installed pnpm is 11.18.0",
            (
                "system Python 3.14.6 lacks jsonschema; package validation uses existing "
                "MCPAudit Python 3.11.15 with jsonschema 4.26.0"
            ),
        ],
    }
    objects = {
        "schema": "FrozenObjectVerificationV1",
        "observed_at_utc": "2026-07-31T16:10:00Z",
        "all_objects_resolve": True,
        "paths": frozen_components(),
        "method": "git cat-file plus committed-blob SHA-256",
    }
    p1 = {
        "schema": "OfflineLockConsistencyReceiptV1",
        "path_id": "P1",
        "status": "FAILED",
        "checks": [
            {"name": "GithubRepoAuditor uv lock --check --offline", "exit_code": 0, "status": "PASS"},
            {
                "name": "PortfolioCommandCenter pinned pnpm 11.5.2 frozen lock",
                "exit_code": 1,
                "status": "UNKNOWN",
                "reason": "pinned pnpm executable was absent from the isolated offline package mirror",
            },
            {
                "name": "PortfolioCommandCenter cargo metadata --locked --offline --no-deps",
                "exit_code": 0,
                "status": "PASS",
            },
        ],
        "repository_writes": 0,
        "package_installs": 0,
    }
    p2 = {
        "schema": "OfflineLockConsistencyReceiptV1",
        "path_id": "P2",
        "status": "VERIFIED",
        "checks": [
            {"name": "MCPAudit uv lock --check --offline", "exit_code": 0, "status": "PASS"},
            {"name": "mcp-trust uv lock --check --offline", "exit_code": 0, "status": "PASS"},
            {"name": "locked MCPAudit wheel and sdist digest presence", "exit_code": 0, "status": "PASS"},
        ],
        "repository_writes": 0,
        "package_installs": 0,
    }
    p3 = {
        "schema": "OfflineLockConsistencyReceiptV1",
        "path_id": "P3",
        "status": "VERIFIED",
        "checks": [{"name": "bridge-db uv lock --check --offline", "exit_code": 0, "status": "PASS"}],
        "repository_writes": 0,
        "package_installs": 0,
    }
    return {"runtime": runtime, "objects": objects, "P1": p1, "P2": p2, "P3": p3}


def path_definitions() -> dict[str, dict[str, Any]]:
    return {
        "p1.json": {
            "schema": "EvidenceConservationPathV1",
            "path_id": "P1",
            "producer_revision": "GithubRepoAuditor@fd61f1c06643c4431460e27aa9210ff8b931ef1d",
            "consumer_revision": "PortfolioCommandCenter@1139cfb9bb1e8d005699f854df368583960e245c",
            "decision_surface": (
                "P1ConsumerInputV1 -> project securityCoverageState and Risk Security overall state"
            ),
            "mutation_axes": ["present", "current", "visible", "consistent", "supported", "bound"],
        },
        "p2.json": {
            "schema": "EvidenceConservationPathV1",
            "path_id": "P2",
            "producer_revision": "MCPAudit@9484d8bb1b059ce48f77015c4a84561675517a77",
            "consumer_revision": "mcp-trust@a30be69132802d2b24157066fa4dc125e8edfdca",
            "decision_surface": "MCPTrustPerServerFixtureAdmissibilityV1",
            "excluded": [
                "GLOBAL_PUBLICATION_READY",
                "REFRESH_PUBLICATION",
                "LIVE_SCAN",
                "SCHEDULER_READINESS",
            ],
            "mutation_axes": ["present", "current", "visible", "consistent", "supported", "bound"],
        },
        "p3.json": {
            "schema": "EvidenceConservationPathV1",
            "path_id": "P3",
            "producer_revision": "bridge-db@b47e5428b0f512c5e4ab87212acdd1d844b365b0",
            "consumer_revision": "BridgeRecoveryReadinessProjection@b47e5428b0f512c5e4ab87212acdd1d844b365b0",
            "decision_surface": "RecoveryAnchorV1 source-current recovery readiness",
            "mutation_axes": ["present", "current", "visible", "consistent", "supported", "bound"],
        },
    }


def _oracle_entries() -> list[dict[str, Any]]:
    entries = []
    for case_id in CASE_TO_FIXTURE:
        path_id = case_id[:2]
        control_case_id = f"{path_id}-C"
        if case_id.endswith("-C"):
            axis = "CONTROL"
            vector = [1, 1, 1, 1, 1, 1]
            authority, disposition = "STRONG", "VALID"
            relation = "CONTROL"
        else:
            suffix = case_id[-2:]
            axis, vector = AXES[suffix]
            authority, disposition = CEILINGS[path_id][suffix]
            relation = "STRICTLY_BELOW_CONTROL"
        entries.append(
            {
                "case_id": case_id,
                "path_id": path_id,
                "control_case_id": control_case_id,
                "evidence_vector": vector,
                "evidence_relation": relation,
                "authority_ceiling": {"authority": authority, "disposition": disposition},
                "disposition": disposition,
                "accepted_reason_families": [disposition.lower()],
                "claim_critical": not case_id.endswith("-C"),
                "rationale": (
                    f"Candidate transcription of the approved {axis.lower()} relation; "
                    "independent adjudication pending."
                ),
                "contract_refs": [f"paths/{path_id.lower()}.json", "spec/evidence-conservation-v1.md"],
            }
        )
    return entries


def _coverage_entries() -> list[dict[str, Any]]:
    entries = []
    for case_id, (classification, source_tests) in COVERAGE.items():
        if classification == "COVERED":
            missing = "none declared by the approved frozen-source review"
            delta = "common sealed oracle only"
        elif classification == "PARTIAL":
            missing = "exact sibling plus normalized relation is not directly asserted"
            delta = "common sealed oracle closes the equivalence judgment"
        else:
            missing = "producer subject and head are dropped before the displayed consumer decision"
            delta = "P1 producer-to-consumer binding seam"
        entries.append(
            {
                "case_id": case_id,
                "classification": classification,
                "source_tests": source_tests,
                "asserted_surface": "frozen path-local behavior identified in the approved coverage review",
                "missing_assertion": missing,
                "cross_contract_delta": delta,
                "reviewer_rationale": "PENDING_INDEPENDENT_REVIEW",
            }
        )
    return entries


def build_records(
    root: Path,
    cases: dict[str, dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
    receipt_hashes: dict[str, str],
) -> None:
    records_root = root / "records"
    boundary = candidate_record(
        schema="BoundaryDecisionV1",
        record_id="boundary-decision-v1",
        spec_sha256=SPEC_SHA256,
        created_at_utc=GENERATED_AT,
        body={
            "strict_downgrade": "REQUIRED",
            "pcc_binding_owner": "PORTFOLIO_COMMAND_CENTER",
            "p2_decision_surface": "PER_SERVER_FIXTURE_GRADE_ADMISSIBILITY",
            "p2_exclusions": [
                "GLOBAL_PUBLICATION_READY",
                "REFRESH_PUBLICATION",
                "LIVE_SCAN",
                "SCHEDULER_READINESS",
            ],
            "approval_evidence": {
                "thread_id": APPROVAL_THREAD_ID,
                "turn_id": APPROVAL_TURN_ID,
                "message_sha256": APPROVAL_MESSAGE_SHA256,
            },
            "contradictions": [],
        },
    )
    write_json(records_root / "boundary-decision-v1.json", boundary)
    components = frozen_components()
    environment = {
        "os": "macOS 26.6; Darwin 25.6.0",
        "architecture": "arm64",
        "runtime_versions": {
            "GithubRepoAuditor": "Python 3.12.13",
            "MCPAudit": "Python 3.11.15",
            "mcp-trust": "Python 3.12.13",
            "bridge-db": "Python 3.12.13",
            "Node": "26.5.0",
            "Rust": "1.97.1",
        },
        "package_manager_versions": {"uv": "0.12.0", "pnpm": "11.18.0", "cargo": "1.97.1"},
        "sqlite_version": sqlite3.sqlite_version,
        "filesystem_semantics": {"filesystem": "APFS", "posix_private_modes": "OBSERVED_LOCAL_ONLY"},
    }
    artifacts = {
        "P1": [],
        "P2": [
            {
                "name": "mcp_audits-2.4.0-py3-none-any.whl",
                "version": "2.4.0",
                "kind": "wheel",
                "sha256": "5a2e18c9271d381a5d5482f7baf2bcd64cd52bdbdfd14cc501c32334b0aac66a",
            },
            {
                "name": "mcp_audits-2.4.0.tar.gz",
                "version": "2.4.0",
                "kind": "sdist",
                "sha256": "a7dd4733d3413d15fabcd2d8aa763b2b95b237b8af99b50d507b98a716a7641d",
            },
        ],
        "P3": [],
    }
    lock_status = {"P1": "FAILED", "P2": "VERIFIED", "P3": "VERIFIED"}
    for path_id in ("P1", "P2", "P3"):
        record = candidate_record(
            schema="FreezeReceiptV1",
            record_id=f"freeze-receipt-{path_id.lower()}-v1",
            spec_sha256=SPEC_SHA256,
            created_at_utc=GENERATED_AT,
            body={
                "path_id": path_id,
                "components": components[path_id],
                "artifacts": artifacts[path_id],
                "resolved_environment": environment,
                "lock_consistency": {
                    "status": lock_status[path_id],
                    "verifier": "OfflineLockConsistencyReceiptV1",
                    "receipt_sha256": receipt_hashes[path_id],
                },
                "clock_contract": "UTC fixed clock; P1 freshness 24h; P2 exact expiry is stale",
                "all_objects_resolve": True,
            },
        )
        write_json(records_root / f"freeze-receipt-{path_id.lower()}-v1.json", record)
    oracle_entries = _oracle_entries()
    oracle = candidate_record(
        schema="OracleAdjudicationV1",
        record_id="oracle-adjudication-v1",
        spec_sha256=SPEC_SHA256,
        created_at_utc=GENERATED_AT,
        body={
            "oracle_id": "evidence-conservation-oracle-v1-candidate",
            "freeze_receipt_ids": ["freeze-receipt-p1-v1", "freeze-receipt-p2-v1", "freeze-receipt-p3-v1"],
            "entries": oracle_entries,
            "reviewers": [
                {"reviewer_id": "reviewer-slot-1", "status": "PENDING_INDEPENDENT_REVIEW"},
                {"reviewer_id": "reviewer-slot-2", "status": "PENDING_INDEPENDENT_REVIEW"},
            ],
            "blindness_attestations": [
                {"reviewer_id": "reviewer-slot-1", "status": "PENDING_INDEPENDENT_REVIEW"},
                {"reviewer_id": "reviewer-slot-2", "status": "PENDING_INDEPENDENT_REVIEW"},
            ],
            "agreement": {"method": "COHENS_KAPPA", "initial_value": None, "initial_disagreements": []},
            "adjudicator": None,
            "final_agreement_count": 0,
            "consumer_outputs_seen": False,
            "sealed_at_utc": None,
            "oracle_sha256": sha256_bytes(canonical_json_bytes(oracle_entries)),
        },
    )
    write_json(records_root / "oracle-adjudication-v1.json", oracle)
    ruleset_sha = sha256_file(root / "policies/secret-patterns-v1.json")
    generator_sha = sha256_file(Path(__file__).resolve())
    controls = {"P1": cases["P1-C"], "P2": cases["P2-C"], "P3": cases["P3-C"]}
    for case_id, fixture_id in CASE_TO_FIXTURE.items():
        path_id = case_id[:2]
        fixture_path = root / "fixtures" / f"{fixture_id}.json"
        fixture_sha = sha256_file(fixture_path)
        control_id = f"{path_id}-C"
        if case_id.endswith("-C"):
            axis = "CONTROL"
            before_vector = after_vector = [1, 1, 1, 1, 1, 1]
            changed_fields: list[str] = []
            parent_sha = fixture_sha
            kind = "CONTROL"
        else:
            suffix = case_id[-2:]
            axis, after_vector = AXES[suffix]
            before_vector = [1, 1, 1, 1, 1, 1]
            changed_fields = semantic_diff_paths(controls[path_id], cases[case_id])
            parent_sha = sha256_file(root / "fixtures" / f"{CASE_TO_FIXTURE[control_id]}.json")
            kind = "MUTATION"
        body = {
            "case_id": case_id,
            "path_id": path_id,
            "family_id": f"{path_id}-FAMILY",
            "control_case_id": control_id,
            "fixture_kind": kind,
            "artifacts": [
                {
                    "ref": f"fixtures/{fixture_id}.json",
                    "media_type": "application/json",
                    "bytes": fixture_path.stat().st_size,
                    "sha256": fixture_sha,
                }
            ],
            "generator": {
                "repository": "MCPAudit",
                "revision": f"sha256:{generator_sha}",
                "config_sha256": generator_sha,
            },
            "provenance": {
                "source_class": "SYNTHETIC_FROM_FIRST_PRINCIPLES",
                "source_ref": f"urn:example:evidence-conservation:{fixture_id}",
                "license": "CC0-1.0",
                "derivation": "deterministic local generator; no live rows or private repository data",
            },
            "rights": {
                "classification": "PROJECT_GENERATED_SYNTHETIC",
                "reviewer": "PENDING_INDEPENDENT_REVIEW",
                "admissible": True,
            },
            "privacy": {"synthetic_only": True, "reserved_identities_only": True, "real_data_present": False},
            "secret_scan": {
                "scanner": "EvidencePackageSecretScanV1",
                "ruleset_sha256": ruleset_sha,
                "findings": 0,
                "allowlist": [],
            },
            "mutation_locality": {
                "axis": axis,
                "parent_sha256": parent_sha,
                "changed_fields": changed_fields,
                "before_vector": before_vector,
                "after_vector": after_vector,
                "favourability_payload_unchanged": case_id != "P2-04",
            },
            "contamination": {
                "opaque_names": True,
                "oracle_fields_visible": False,
                "mutation_label_visible": False,
            },
        }
        record = candidate_record(
            schema="FixtureAdmissibilityV1",
            record_id=f"fixture-admissibility-{fixture_id}-v1",
            spec_sha256=SPEC_SHA256,
            created_at_utc=GENERATED_AT,
            body=body,
        )
        write_json(records_root / "fixture-admissibility" / f"{fixture_id}-v1.json", record)
    profiles = [
        {
            "profile_id": "darwin-arm64-generator-observed",
            "os": "macOS 26.6; Darwin 25.6.0",
            "architecture": "arm64",
            "runtimes": environment["runtime_versions"],
            "package_managers": environment["package_manager_versions"],
            "sqlite_version": sqlite3.sqlite_version,
            "timezone": "UTC",
            "locale": "C",
            "encoding": "UTF-8",
            "fixed_clock": "2030-01-02T12:00:00Z",
            "random_seed": 20260731,
            "python_hash_seed": 0,
            "environment_allowlist": ["LANG", "LC_ALL", "PATH", "PYTHONHASHSEED", "TZ"],
            "filesystem_semantics": {"filesystem": "APFS", "posix_private_modes": "OBSERVED_LOCAL_ONLY"},
            "network_denial": "OFFLINE_FLAGS_AND_NO_CONNECTOR_INPUTS",
            "subprocess_policy": "GENERATOR_AND_VALIDATOR_ONLY; NO_CONSUMERS",
            "writable_roots": ["PACKAGE_ROOT", "ISOLATED_DISPOSABLE_TEMP"],
            "canonicalization_exclusions": ["padding", "run_id", "runtime_timestamp"],
            "repeat_count": 10,
        },
        {
            "profile_id": "independent-profile-slot",
            "os": "PENDING_INDEPENDENT_REVIEW",
            "architecture": "PENDING_INDEPENDENT_REVIEW",
            "runtimes": {"status": "PENDING_INDEPENDENT_REVIEW"},
            "package_managers": {"status": "PENDING_INDEPENDENT_REVIEW"},
            "sqlite_version": "PENDING_INDEPENDENT_REVIEW",
            "timezone": "UTC",
            "locale": "C",
            "encoding": "UTF-8",
            "fixed_clock": "2030-01-02T12:00:00Z",
            "random_seed": 20260731,
            "python_hash_seed": 0,
            "environment_allowlist": ["LANG", "LC_ALL", "PATH", "PYTHONHASHSEED", "TZ"],
            "filesystem_semantics": {"status": "PENDING_INDEPENDENT_REVIEW"},
            "network_denial": "PENDING_INDEPENDENT_REVIEW",
            "subprocess_policy": "GENERATOR_AND_VALIDATOR_ONLY; NO_CONSUMERS",
            "writable_roots": ["PACKAGE_ROOT", "ISOLATED_DISPOSABLE_TEMP"],
            "canonicalization_exclusions": ["padding", "run_id", "runtime_timestamp"],
            "repeat_count": 10,
        },
    ]
    determinism = candidate_record(
        schema="DeterminismProfileV1",
        record_id="determinism-profile-v1",
        spec_sha256=SPEC_SHA256,
        created_at_utc=GENERATED_AT,
        body={
            "profiles": profiles,
            "freeze_receipt_ids": ["freeze-receipt-p1-v1", "freeze-receipt-p2-v1", "freeze-receipt-p3-v1"],
            "preflight_results": [
                {
                    "profile_id": "darwin-arm64-generator-observed",
                    "status": "PARTIAL",
                    "reason": "local observation is not independent admission",
                },
                {"profile_id": "independent-profile-slot", "status": "PENDING_INDEPENDENT_REVIEW"},
            ],
            "profile_sha256": sha256_bytes(canonical_json_bytes(profiles)),
        },
    )
    write_json(records_root / "determinism-profile-v1.json", determinism)
    coverage_entries = _coverage_entries()
    coverage = candidate_record(
        schema="CoverageDeltaV1",
        record_id="coverage-delta-v1",
        spec_sha256=SPEC_SHA256,
        created_at_utc=GENERATED_AT,
        body={
            "freeze_receipt_ids": ["freeze-receipt-p1-v1", "freeze-receipt-p2-v1", "freeze-receipt-p3-v1"],
            "entries": coverage_entries,
            "primary_counts": {"covered": 10, "partial": 7, "cross_contract": 1},
            "unmapped_count": 0,
            "new_claim": (
                "common independently sealed oracle plus the P1 producer-subject-head binding seam only"
            ),
            "coverage_sha256": sha256_bytes(canonical_json_bytes(coverage_entries)),
        },
    )
    write_json(records_root / "coverage-delta-v1.json", coverage)


def _initial_summary() -> dict[str, Any]:
    return {
        "schema": "EvidencePackageAdmissionSummaryV1",
        "spec_sha256": SPEC_SHA256,
        "generated_at_utc": GENERATED_AT,
        "terminal_state": "BLOCKED_CONTRACT",
        "record_counts": {
            "total": 29,
            "candidate": 29,
            "admitted": 0,
            "pending_independent_review": 29,
            "failed_local_admission_gate": 1,
        },
        "fixture_counts": {"total": 21, "controls": 3, "one_axis_mutations": 18},
        "checks": [
            {"name": "package validation", "status": "PENDING", "detail": "run tools/validate_package.py"}
        ],
        "deterministic_regeneration": {
            "schema": "DeterministicRegenerationV1",
            "status": "SKIPPED",
            "byte_identical": None,
            "compared_files": 0,
            "mismatches": [],
        },
        "independent_review": {
            "status": "PENDING_INDEPENDENT_REVIEW",
            "required_records": 29,
            "completed_records": 0,
            "oracle_reviewers_required": 2,
            "second_environment_required": True,
        },
        "remote_lease": {
            "branch": "codex/evidence-conservation-package-20260731",
            "base_sha": "0e101cbfb9136bf62b38e668a15af9f683cde48e",
            "remote_tip_expected": "0e101cbfb9136bf62b38e668a15af9f683cde48e",
            "further_remote_effects_authorized": False,
        },
        "authorization_boundary": (
            "No consumer invocation or primary case execution; a separate operator "
            "authorization is required after independent admission."
        ),
    }


def _write_readme(root: Path) -> None:
    text = """# Evidence Conservation evidence package candidate

This subtree contains only the `EVIDENCE_PACKAGE_ONLY` phase: the approved canonical specification,
three frozen path definitions, 21 opaque synthetic primary fixtures, 29 prerequisite record candidates,
schemas, deterministic generators, offline validators, focused tests, and admission outputs.

It does not invoke PortfolioCommandCenter, mcp-trust, BridgeDB consumer logic, MCPAudit scans, or any
primary pilot case. Every record remains `CANDIDATE`; independent review is explicitly pending. The
single known local admission failure is P1's unavailable exact pnpm 11.5.2 executable in the isolated
offline mirror, while the installed pnpm is 11.18.0.

Run the focused validator and tests with the existing local MCPAudit virtual environment only. Do not
install or update dependencies.
"""
    (root / "README.md").write_text(text, encoding="utf-8")


def _write_initial_report(root: Path) -> None:
    text = """# Evidence-package admission report

State: `BLOCKED_CONTRACT`

The package has 21 synthetic fixture candidates and 29 prerequisite record candidates. No record is
admitted. Independent review is pending for all 29 records. P1 also has a local freeze-gate failure:
the exact pinned pnpm 11.5.2 executable was unavailable in the isolated offline mirror, and no install
or update was attempted. Run the offline validator to replace this provisional report with checked
results. No outcome in this report authorizes consumer execution.
"""
    (root / "admission-report.md").write_text(text, encoding="utf-8")


def _write_generation_manifest(root: Path) -> None:
    excluded = [
        "admission-report.md",
        "admission-summary.json",
        "generation-manifest.json",
        "records/ownership-preflight-v1.json",
        "tests/",
        "tools/",
        "verification/deterministic-regeneration.json",
    ]
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if any(relative == item or (item.endswith("/") and relative.startswith(item)) for item in excluded):
            continue
        files.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "role": "DETERMINISTIC_ARTIFACT",
            }
        )
    manifest = {
        "schema": "EvidencePackageGenerationManifestV1",
        "spec_sha256": SPEC_SHA256,
        "generated_at_utc": GENERATED_AT,
        "files": files,
        "deterministic_artifacts": [item["path"] for item in files],
        "excluded_from_regeneration": excluded,
    }
    write_json(root / "generation-manifest.json", manifest)


def build(
    root: Path, *, spec_source_jsonl: Path | None, spec_file: Path | None, ownership_file: Path
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    spec_bytes = extract_approved_spec(spec_source_jsonl) if spec_source_jsonl else spec_file.read_bytes()  # type: ignore[union-attr]
    if sha256_bytes(spec_bytes) != SPEC_SHA256:
        raise ValueError("canonical specification digest mismatch")
    spec_path = root / "spec" / "evidence-conservation-v1.md"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_bytes(spec_bytes)
    (root / "spec" / "evidence-conservation-v1.sha256").write_text(
        f"{SPEC_SHA256}  evidence-conservation-v1.md\n", encoding="utf-8"
    )
    target_ownership = root / "records" / "ownership-preflight-v1.json"
    if ownership_file.resolve() != target_ownership.resolve():
        target_ownership.parent.mkdir(parents=True, exist_ok=True)
        target_ownership.write_bytes(ownership_file.read_bytes())
    ownership = read_json(target_ownership)
    if ownership["content_sha256"] != record_content_sha256(ownership):
        raise ValueError("ownership record digest mismatch")
    schemas = build_schemas()
    for name, schema in schemas.items():
        write_json(root / "schemas" / name, schema)
    secret_policy = {
        "schema": "EvidencePackageSecretPatternsV1",
        "patterns": [
            {"id": "private-key", "regex": "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"},
            {"id": "aws-access-key", "regex": "AKIA[0-9A-Z]{16}"},
            {"id": "github-token", "regex": "gh[pousr]_[A-Za-z0-9]{20,}"},
            {"id": "bearer-token", "regex": "(?i)bearer[ ]+[A-Za-z0-9._-]{16,}"},
            {"id": "assigned-secret", "regex": "(?i)(?:password|secret|token)[ ]*[:=][ ]*[^\\s]{8,}"},
        ],
    }
    privacy_policy = {
        "schema": "EvidencePackagePrivacyLocalityV1",
        "reserved_domains": ["example.invalid"],
        "forbidden_fragments": ["/Users/", "/home/", "bridge.db", "saagpatel", "api_key", "access_token"],
        "forbidden_metadata_keys": [
            "mutation_axis",
            "expected_verdict",
            "authority_ceiling",
            "oracle",
            "case_id",
            "control_case_id",
        ],
        "semantic_diff_exclusions": ["/padding"],
    }
    write_json(root / "policies" / "secret-patterns-v1.json", secret_policy)
    write_json(root / "policies" / "privacy-locality-v1.json", privacy_policy)
    receipts = verification_receipts()
    write_json(root / "verification" / "runtime-observation.json", receipts["runtime"])
    write_json(root / "verification" / "frozen-object-verification.json", receipts["objects"])
    receipt_hashes = {}
    for path_id in ("P1", "P2", "P3"):
        receipt_path = root / "verification" / f"lock-consistency-{path_id.lower()}.json"
        write_json(receipt_path, receipts[path_id])
        receipt_hashes[path_id] = sha256_file(receipt_path)
    for name, definition in path_definitions().items():
        write_json(root / "paths" / name, definition)
    contracts = {
        "schema": "FrozenContractReferencesV1",
        "spec_sha256": SPEC_SHA256,
        "paths": path_definitions(),
        "components": frozen_components(),
        "excluded_live_inputs": [
            "BridgeDB rows",
            "PortfolioTruth current output",
            "open PR heads",
            "connectors",
            "credentials",
            "schedulers",
            "hosts",
        ],
    }
    write_json(root / "contracts" / "frozen-contracts-v1.json", contracts)
    cases, fixtures = build_fixtures()
    for fixture_id, fixture in fixtures.items():
        write_json(root / "fixtures" / f"{fixture_id}.json", fixture)
    build_records(root, cases, fixtures, receipt_hashes)
    _write_readme(root)
    write_json(root / "admission-summary.json", _initial_summary())
    _write_initial_report(root)
    write_json(
        root / "verification" / "deterministic-regeneration.json",
        {
            "schema": "DeterministicRegenerationV1",
            "status": "PENDING",
            "byte_identical": None,
            "compared_files": 0,
            "mismatches": [],
        },
    )
    _write_generation_manifest(root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the offline Evidence Conservation package")
    parser.add_argument("--package-root", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--spec-source-jsonl", type=Path)
    source.add_argument("--spec-file", type=Path)
    parser.add_argument("--ownership-file", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    build(
        args.package_root,
        spec_source_jsonl=args.spec_source_jsonl,
        spec_file=args.spec_file,
        ownership_file=args.ownership_file,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
