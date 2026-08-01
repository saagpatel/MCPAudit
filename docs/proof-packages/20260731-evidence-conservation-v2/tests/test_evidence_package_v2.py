"""Focused offline tests for the repaired v2 evidence-package candidate."""

from __future__ import annotations

import base64
import copy
import json
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from materialize_fixture import materialize  # noqa: E402
from package_lib import (  # noqa: E402
    ALL_CASE_IDS,
    P2_RECEIPT_REF,
    PACKAGE_ID,
    STATIC_RELATIVE_PATHS,
    STRUCTURAL_SEMANTIC_AUTHORITY,
    admission_summary_semantic_errors,
    build_package,
    canonical_json_bytes,
    declared_oracle_consistency_errors,
    near_miss_boundaries,
    no_op_boundaries,
    ownership_semantic_errors,
    record_semantic_errors,
    sha256_bytes,
    tar_members,
    validate_package,
)


def _load(relative: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((ROOT / relative).read_text()))


def _fixture(case_id: str) -> dict[str, Any]:
    suffix = case_id.split("-", maxsplit=1)[1]
    name = "control" if suffix == "C" else suffix
    return _load(f"fixtures/{case_id[:2].lower()}-{name}.json")


def _artifact(fixture: dict[str, Any], name: str) -> bytes:
    row = next(item for item in fixture["artifacts"] if item["name"] == name)
    return base64.b64decode(row["content_base64"])


def _schema_rejects(instance: dict[str, Any], relative: str) -> bool:
    schema = _load(relative)
    return bool(list(jsonschema.Draft202012Validator(schema).iter_errors(instance)))


def _approving_reviews(content_sha256: str, spec_sha256: str) -> list[dict[str, Any]]:
    return [
        {
            "receipt_id": f"review-adversarial-{suffix}",
            "reviewer_id": reviewer_id,
            "review_type": review_type,
            "decision": "APPROVE",
            "reviewed_content_sha256": content_sha256,
            "reviewed_spec_sha256": spec_sha256,
            "completed_at": "2026-07-31T21:27:04Z",
            "independent": True,
        }
        for suffix, reviewer_id, review_type in (
            ("a", "v2-oracle-reviewer", "ORACLE_CONTRACT"),
            ("b", "v2-fixture-reviewer", "FIXTURE_REPRODUCIBILITY"),
        )
    ]


def test_full_package_validation_and_captured_receipt_pass() -> None:
    result = validate_package(ROOT, jsonschema)
    assert result["status"] == "PASS", result["errors"]
    assert result["file_count"] == 100
    assert result["fixture_count"] == 21
    assert result["record_count"] == 29
    assert result["schema_count"] == 19
    assert result["semantic_authority"] == STRUCTURAL_SEMANTIC_AUTHORITY
    assert result["stored_receipt_matches"] is True
    assert _load("verification/package-validation.json") == result


def test_primary_boundary_and_record_counts_are_exact() -> None:
    summary = _load("admission-summary.json")
    assert summary["primary_corpus"] == {"controls": 3, "mutations": 18, "total": 21}
    assert summary["boundaries"] == {"no_op": 6, "near_miss": 6}
    assert summary["coverage"] == {"covered": 11, "partial": 6, "cross": 1}
    assert summary["record_counts"]["total"] == 29
    assert summary["runtime_execution"]["cases_executed"] == 0
    assert summary["runtime_execution"]["completed_case_ids"] == []
    assert summary["review_receipts"] == []


def test_p3_native_topology_and_discriminators_are_uncontaminated() -> None:
    for case_id in ("P3-C", "P3-02", "P3-03", "P3-04", "P3-05", "P3-06"):
        fixture = _fixture(case_id)
        members = tar_members(_artifact(fixture, "recovery-anchor.tar"))
        file_members = {name for name, (content, _mode) in members.items() if content is not None}
        assert file_members == {"anchor.sqlite", "manifest.json"}
        assert "anchor.json" not in members
    assert len(_fixture("P3-01")["artifacts"]) == 1

    digest_case = tar_members(_artifact(_fixture("P3-03"), "recovery-anchor.tar"))
    size_case = tar_members(_artifact(_fixture("P3-04"), "recovery-anchor.tar"))
    digest_manifest_bytes = digest_case["manifest.json"][0]
    size_manifest_bytes = size_case["manifest.json"][0]
    size_anchor_bytes = size_case["anchor.sqlite"][0]
    assert digest_manifest_bytes is not None
    assert size_manifest_bytes is not None
    assert size_anchor_bytes is not None
    digest_manifest = json.loads(digest_manifest_bytes)
    size_manifest = json.loads(size_manifest_bytes)
    assert digest_manifest["sha256"] == "REDACTED_SHA256"
    assert size_manifest["backup_bytes"] == len(size_anchor_bytes) + 1


def test_p3_06_changes_only_native_database_mode() -> None:
    control = _fixture("P3-C")
    mode_case = _fixture("P3-06")
    assert _artifact(control, "source.sqlite") == _artifact(mode_case, "source.sqlite")
    before = tar_members(_artifact(control, "recovery-anchor.tar"))
    after = tar_members(_artifact(mode_case, "recovery-anchor.tar"))
    assert before["anchor.sqlite"][0] == after["anchor.sqlite"][0]
    assert before["manifest.json"][0] == after["manifest.json"][0]
    assert before["anchor.sqlite"][1] == 0o600
    assert after["anchor.sqlite"][1] == 0o644
    assert mode_case["expected"]["raw_signal"]["source_current"] == "ABSENT"


def test_p3_materializer_writes_only_native_names_and_modes(tmp_path: Path) -> None:
    for case_id in ("P3-C", "P3-01", "P3-02", "P3-03", "P3-04", "P3-05", "P3-06"):
        destination = tmp_path / case_id
        materialize(_fixture(case_id), destination)
        anchor_root = destination / "recovery-anchor"
        if case_id == "P3-01":
            assert not anchor_root.exists()
            continue
        assert {path.name for path in anchor_root.iterdir()} == {"anchor.sqlite", "manifest.json"}
        assert stat.S_IMODE(anchor_root.stat().st_mode) == 0o700
        assert stat.S_IMODE((anchor_root / "manifest.json").stat().st_mode) == 0o600
        expected_mode = 0o644 if case_id == "P3-06" else 0o600
        assert stat.S_IMODE((anchor_root / "anchor.sqlite").stat().st_mode) == expected_mode


def test_p2_native_receipt_qualified_discriminators_are_exact() -> None:
    expected = {
        "P2-04": f"fresh_scan_binding_mismatch:{P2_RECEIPT_REF}",
        "P2-05": f"successful_scan_receipt_schema_invalid:{P2_RECEIPT_REF}",
        "P2-06": f"successful_scan_receipt_mismatch:{P2_RECEIPT_REF}",
    }
    for case_id, reason in expected.items():
        fixture = _fixture(case_id)
        assert fixture["expected"]["raw_signal"] == {"error": reason}
    assert _fixture("P2-04")["expected"]["reason_family"] == expected["P2-04"]
    assert _fixture("P2-06")["expected"]["reason_family"] == expected["P2-06"]


def test_boundary_pairs_use_real_frozen_edges_without_primary_duplication() -> None:
    no_op = no_op_boundaries()
    near = near_miss_boundaries()
    assert no_op["count"] == near["count"] == 6
    ids = [row["boundary_id"] for corpus in (no_op, near) for row in corpus["entries"]]
    assert len(ids) == len(set(ids)) == 12
    assert not set(ids) & set(ALL_CASE_IDS)
    assert "MANIFEST.json.created_at" in no_op["entries"][3]["inside"]
    assert len(no_op["entries"][3]["required_rebindings"]) == 5
    assert near["entries"][3]["inside"] == "receipt approval is exactly {approval_ref: null}"
    assert "approval.approval_ref" in near["entries"][3]["outside"]
    assert "format_version" not in near["entries"][3]["outside"]


def test_terminal_record_bypasses_are_rejected() -> None:
    record = _load("records/fixture-admissibility/p1-control-v1.json")
    spec_digest = record["spec_sha256"]
    admitted = copy.deepcopy(record)
    admitted["body"]["admitted"] = True
    admitted["body"]["independent_review"] = "COMPLETE"
    admitted["content_sha256"] = sha256_bytes(canonical_json_bytes(admitted["body"]))
    admitted.update(
        {
            "candidate_state": "TERMINAL_ADMITTED",
            "admission_state": "ADMITTED",
            "prerequisite_state": "SATISFIED",
            "reviews": _approving_reviews(admitted["content_sha256"], spec_digest),
        }
    )
    assert not _schema_rejects(admitted, "schemas/fixture-admissibility-v1.schema.json")
    assert record_semantic_errors(admitted, spec_digest) == []

    duplicate = copy.deepcopy(admitted)
    duplicate["reviews"][1]["reviewer_id"] = duplicate["reviews"][0]["reviewer_id"]
    assert "record_duplicate_reviewer_id" in record_semantic_errors(duplicate, spec_digest)

    rejecting = copy.deepcopy(admitted)
    rejecting["reviews"][0]["decision"] = "REJECT"
    assert _schema_rejects(rejecting, "schemas/fixture-admissibility-v1.schema.json")
    assert "record_admitted_non_approving_review" in record_semantic_errors(rejecting, spec_digest)

    stale_review = copy.deepcopy(admitted)
    stale_review["reviews"][0]["reviewed_content_sha256"] = "0" * 64
    assert "record_review_content_sha256_mismatch" in record_semantic_errors(stale_review, spec_digest)

    stale_hash = copy.deepcopy(record)
    stale_hash["body"]["admitted"] = True
    assert "record_content_sha256_mismatch" in record_semantic_errors(stale_hash, spec_digest)

    arbitrary = copy.deepcopy(record)
    arbitrary["body"] = {"arbitrary": True}
    assert _schema_rejects(arbitrary, "schemas/fixture-admissibility-v1.schema.json")

    malformed = copy.deepcopy(admitted)
    malformed["reviews"][0]["review_type"] = "MALFORMED"
    assert _schema_rejects(malformed, "schemas/fixture-admissibility-v1.schema.json")

    contradiction = copy.deepcopy(record)
    contradiction["candidate_state"] = "TERMINAL_REJECTED"
    assert _schema_rejects(contradiction, "schemas/fixture-admissibility-v1.schema.json")

    contradictory_body = copy.deepcopy(admitted)
    contradictory_body["body"]["admitted"] = False
    contradictory_body["content_sha256"] = sha256_bytes(canonical_json_bytes(contradictory_body["body"]))
    contradictory_body["reviews"] = _approving_reviews(contradictory_body["content_sha256"], spec_digest)
    assert _schema_rejects(contradictory_body, "schemas/fixture-admissibility-v1.schema.json")
    assert "record_admitted_fixture_body_not_terminal" in record_semantic_errors(
        contradictory_body, spec_digest
    )


def test_ownership_terminal_transition_binds_content_spec_and_review_types() -> None:
    ownership = _load("records/ownership-preflight-v1.json")
    spec_digest = ownership["spec_sha256"]
    assert ownership_semantic_errors(ownership, spec_digest) == []

    admitted = copy.deepcopy(ownership)
    admitted["candidate_state"] = "TERMINAL_ADMITTED"
    admitted["admission_state"] = "ADMITTED"
    admitted["review"]["independent_review_status"] = "COMPLETE"
    admitted["content_sha256"] = sha256_bytes(
        canonical_json_bytes(
            {
                key: value
                for key, value in admitted.items()
                if key
                not in {
                    "candidate_state",
                    "admission_state",
                    "prerequisite_state",
                    "reviews",
                    "content_sha256",
                }
            }
        )
    )
    admitted["reviews"] = _approving_reviews(admitted["content_sha256"], spec_digest)
    assert not _schema_rejects(admitted, "schemas/ownership-preflight-v1.schema.json")
    assert ownership_semantic_errors(admitted, spec_digest) == []

    wrong_types = copy.deepcopy(admitted)
    wrong_types["reviews"][1]["review_type"] = "ORACLE_CONTRACT"
    assert _schema_rejects(wrong_types, "schemas/ownership-preflight-v1.schema.json")
    assert "ownership_admitted_review_types" in ownership_semantic_errors(wrong_types, spec_digest)

    stale = copy.deepcopy(admitted)
    stale["writer_lease"]["verified_tip"] = "f" * 40
    assert "ownership_content_sha256_mismatch" in ownership_semantic_errors(stale, spec_digest)


def test_admitted_summary_without_reviews_prerequisites_and_cases_is_rejected() -> None:
    summary = _load("admission-summary.json")
    records = {
        record["record_id"]: record
        for path in (ROOT / "records").rglob("*.json")
        for record in [json.loads(path.read_text())]
    }
    admitted_records = copy.deepcopy(records)
    for record in admitted_records.values():
        record["candidate_state"] = "TERMINAL_ADMITTED"
        record["admission_state"] = "ADMITTED"
        record["prerequisite_state"] = "SATISFIED"

    admitted = copy.deepcopy(summary)
    admitted.update(
        {
            "candidate_state": "TERMINAL_ADMITTED",
            "admission_state": "ADMITTED",
            "independent_review": {
                "required_count": 2,
                "completed_count": 2,
                "status": "COMPLETE",
            },
            "review_receipts": _approving_reviews(
                admitted["review_subject_sha256"], admitted["review_subject_sha256"]
            ),
            "prerequisite_records": {
                "required_count": 29,
                "satisfied_count": 29,
                "admitted_count": 29,
                "status": "COMPLETE",
            },
            "runtime_execution": {
                "authorized": True,
                "cases_executed": 21,
                "total_cases": 21,
                "completed_case_ids": list(ALL_CASE_IDS),
            },
            "p1_freeze": "PASS_EXACT_PNPM_11_5_2",
            "p3_posix_environment": "PASS",
            "claim_ceiling": "ADMITTED_FOR_AUTHORIZED_BASELINE_ONLY",
        }
    )
    assert not _schema_rejects(admitted, "schemas/admission-summary-v2.schema.json")
    assert (
        admission_summary_semantic_errors(admitted, admitted_records, summary["review_subject_sha256"]) == []
    )

    missing_reviews = copy.deepcopy(admitted)
    missing_reviews["review_receipts"] = []
    assert _schema_rejects(missing_reviews, "schemas/admission-summary-v2.schema.json")
    assert "summary_admitted_reviews_incomplete" in admission_summary_semantic_errors(
        missing_reviews, admitted_records, summary["review_subject_sha256"]
    )

    duplicate_reviewer = copy.deepcopy(admitted)
    duplicate_reviewer["review_receipts"][1]["reviewer_id"] = duplicate_reviewer["review_receipts"][0][
        "reviewer_id"
    ]
    assert "summary_duplicate_reviewer_id" in admission_summary_semantic_errors(
        duplicate_reviewer, admitted_records, summary["review_subject_sha256"]
    )

    rejecting_review = copy.deepcopy(admitted)
    rejecting_review["review_receipts"][0]["decision"] = "REJECT"
    assert _schema_rejects(rejecting_review, "schemas/admission-summary-v2.schema.json")

    stale_review = copy.deepcopy(admitted)
    stale_review["review_receipts"][0]["reviewed_content_sha256"] = "0" * 64
    assert "summary_review_content_sha256_mismatch" in admission_summary_semantic_errors(
        stale_review, admitted_records, summary["review_subject_sha256"]
    )

    incomplete_records = copy.deepcopy(admitted_records)
    first_record = next(iter(incomplete_records.values()))
    first_record["candidate_state"] = "READY_FOR_INDEPENDENT_REVIEW"
    first_record["admission_state"] = "PENDING_INDEPENDENT_REVIEW"
    assert "summary_admitted_prerequisite_records_incomplete" in admission_summary_semantic_errors(
        admitted, incomplete_records, summary["review_subject_sha256"]
    )

    incomplete_cases = copy.deepcopy(admitted)
    incomplete_cases["runtime_execution"]["cases_executed"] = 20
    incomplete_cases["runtime_execution"]["completed_case_ids"] = list(ALL_CASE_IDS[:-1])
    assert _schema_rejects(incomplete_cases, "schemas/admission-summary-v2.schema.json")
    assert "summary_admitted_cases_incomplete" in admission_summary_semantic_errors(
        incomplete_cases, admitted_records, summary["review_subject_sha256"]
    )

    wrong_environment = copy.deepcopy(admitted)
    wrong_environment["p1_freeze"] = "UNKNOWN_EXACT_PNPM_11_5_2"
    assert _schema_rejects(wrong_environment, "schemas/admission-summary-v2.schema.json")
    assert "summary_admitted_environment_or_claim_incomplete" in admission_summary_semantic_errors(
        wrong_environment, admitted_records, summary["review_subject_sha256"]
    )


def test_path_specific_fixture_schema_rejects_case_coordinate_artifact_and_reason_escapes() -> None:
    mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("fixture_id", lambda fixture: fixture.__setitem__("fixture_id", "P1-C")),
        (
            "coordinates",
            lambda fixture: fixture.__setitem__("evidence_coordinates", {"arbitrary": 1}),
        ),
        (
            "artifact_name",
            lambda fixture: fixture["artifacts"][0].__setitem__("name", "arbitrary.bin"),
        ),
        (
            "reason_family",
            lambda fixture: fixture["expected"].__setitem__("reason_family", "manufactured"),
        ),
    )
    for label, mutate in mutations:
        invalid = _fixture("P3-C")
        mutate(invalid)
        assert _schema_rejects(invalid, "schemas/p3-full-fixture-v2.schema.json"), label


def test_fixture_and_oracle_declarations_are_separate_and_spec_bound() -> None:
    fixtures = {case_id: _fixture(case_id) for case_id in ALL_CASE_IDS}
    oracle = _load("records/oracle-adjudication-v1.json")["body"]["sealed_matrix"]
    spec = (ROOT / "spec/evidence-conservation-v2.md").read_text()
    assert declared_oracle_consistency_errors(fixtures, oracle, spec) == []

    corrupted_fixture = copy.deepcopy(fixtures)
    corrupted_fixture["P3-C"]["expected"]["reason_family"] = "corrupted"
    assert declared_oracle_consistency_errors(corrupted_fixture, oracle, spec)

    corrupted_oracle = copy.deepcopy(oracle)
    corrupted_oracle["P3-C"]["reason_family"] = "corrupted"
    assert declared_oracle_consistency_errors(fixtures, corrupted_oracle, spec)
    assert declared_oracle_consistency_errors(corrupted_fixture, corrupted_oracle, spec)
    assert STRUCTURAL_SEMANTIC_AUTHORITY.startswith("OUTSIDE_STRUCTURAL_VALIDATION")


def test_frozen_closure_is_bounded_overinclusive_and_residual_unknowns_are_explicit() -> None:
    frozen = _load("contracts/frozen-contracts-v2.json")
    assert frozen["claim_ceiling"] == "BOUNDED_REPOSITORY_LOCAL_CLOSURE_ONLY"
    assert frozen["residual_unknowns"]
    by_name = {row["name"]: row for row in frozen["repositories"]}
    assert "src/portfolio_context_recovery.py" in {
        row["path"] for row in by_name["GithubRepoAuditor"]["sources"]
    }
    assert "src/App.tsx" in {row["path"] for row in by_name["PortfolioCommandCenter"]["sources"]}
    assert "tests/conftest.py" in {row["path"] for row in by_name["MCPAudit"]["sources"]}
    assert "src/bridge_db/auth.py" in {row["path"] for row in by_name["bridge-db"]["sources"]}
    assert {name: row["source_count"] for name, row in by_name.items()} == {
        "GithubRepoAuditor": 474,
        "PortfolioCommandCenter": 35,
        "MCPAudit": 138,
        "mcp-trust": 74,
        "bridge-db": 81,
    }


def test_bridge_failure_and_environment_gaps_remain_honest() -> None:
    summary = _load("admission-summary.json")
    boundary = _load("records/boundary-decision-v1.json")["body"]
    environment = _load("verification/environment-capabilities.json")
    determinism = _load("records/determinism-profile-v1.json")["body"]
    assert summary["bridge_postflight"]["receipt_written"] is False
    assert boundary["bridge_postflight"]["retry_authorized"] is False
    assert environment["pnpm_11_5_2"]["status"] == "UNKNOWN"
    assert environment["pnpm_11_5_2"]["package_manager_invoked"] is False
    assert determinism["second_supported_environment"]["status"] == "PENDING_INDEPENDENT_REVIEW"
    assert _load("paths/p1.json")["producer_head_behavior"] == "UNKNOWN_UNMUTATED_UNCLAIMED"


def test_unexpected_sidecar_boundary_is_fixed_and_non_primary() -> None:
    sidecar = near_miss_boundaries()["entries"][5]
    assert sidecar["boundary_id"] == "NEAR-06"
    assert base64.b64decode(sidecar["outside_artifact"]["content_base64"]) == b"untracked"
    assert sidecar["outside_artifact"]["name"] == "anchor.sqlite-wal"
    assert sidecar["outside_reason"] == "anchor_artifact_set_mismatch"


def test_full_disposable_regeneration_is_byte_identical(tmp_path: Path) -> None:
    regenerated = tmp_path / PACKAGE_ID
    regenerated.mkdir()
    for relative in STATIC_RELATIVE_PATHS:
        source = ROOT / relative
        destination = regenerated / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    result = build_package(regenerated)
    assert result["status"] == "PASS"
    original_files = sorted(path.relative_to(ROOT) for path in ROOT.rglob("*") if path.is_file())
    regenerated_files = sorted(
        path.relative_to(regenerated) for path in regenerated.rglob("*") if path.is_file()
    )
    assert original_files == regenerated_files
    assert len(original_files) == 100
    for relative_path in original_files:
        assert (ROOT / relative_path).read_bytes() == (regenerated / relative_path).read_bytes(), (
            relative_path
        )
