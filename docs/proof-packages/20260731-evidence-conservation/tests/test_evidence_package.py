from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = PACKAGE_ROOT / "tools"
sys.path.insert(0, str(TOOLS_ROOT))

from build_package import _initial_summary  # noqa: E402
from package_lib import record_content_sha256  # noqa: E402
from validate_package import (  # noqa: E402
    allowed_write_errors,
    deterministic_regeneration,
    digest_errors,
    inventory_errors,
    locality_errors,
    privacy_contamination_errors,
    provenance_rights_errors,
    schema_errors,
    secret_errors,
)


def test_exact_fixture_and_record_inventories() -> None:
    assert inventory_errors(PACKAGE_ROOT) == []
    assert len(list((PACKAGE_ROOT / "fixtures").glob("*.json"))) == 21
    assert len(list((PACKAGE_ROOT / "records").rglob("*.json"))) == 29


def test_all_records_and_fixtures_validate_against_schemas() -> None:
    assert schema_errors(PACKAGE_ROOT) == []


def test_provisional_summary_is_schema_valid_and_fail_closed() -> None:
    schema = json.loads(
        (PACKAGE_ROOT / "schemas" / "admission-summary-v1.schema.json").read_text(encoding="utf-8")
    )
    summary = _initial_summary()
    assert summary["terminal_state"] == "BLOCKED_CONTRACT"
    Draft202012Validator(schema).validate(summary)


def test_path_payload_schemas_reject_unapproved_fields() -> None:
    schemas = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (PACKAGE_ROOT / "schemas").glob("p*-v1.schema.json")
    }
    schema_for_contract = {
        "P1ConsumerInputV1": "p1-consumer-input-v1.schema",
        "MCPTrustPerServerFixtureAdmissibilityV1": "p2-fixture-admissibility-v1.schema",
        "BridgeRecoveryReadinessFixtureV1": "p3-recovery-fixture-v1.schema",
    }
    for fixture_path in (PACKAGE_ROOT / "fixtures").glob("*.json"):
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        payload = dict(fixture["payload"])
        payload["unapproved_field"] = True
        validator = Draft202012Validator(schemas[schema_for_contract[fixture["path_contract"]]])
        assert not validator.is_valid(payload)


def test_spec_record_and_artifact_digests_are_bound() -> None:
    assert digest_errors(PACKAGE_ROOT) == []
    record_path = PACKAGE_ROOT / "records" / "boundary-decision-v1.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["body"]["strict_downgrade"] = "TAMPERED"
    assert record["content_sha256"] != record_content_sha256(record)


def test_provenance_rights_and_locality_checks_pass() -> None:
    assert provenance_rights_errors(PACKAGE_ROOT) == []
    assert locality_errors(PACKAGE_ROOT) == []


def test_p2_contradiction_changes_only_fresh_grade_digest_closure() -> None:
    records = {
        json.loads(path.read_text(encoding="utf-8"))["body"]["case_id"]: json.loads(
            path.read_text(encoding="utf-8")
        )["body"]
        for path in (PACKAGE_ROOT / "records" / "fixture-admissibility").glob("*.json")
    }
    control = records["P2-C"]
    contradiction = records["P2-04"]
    assert contradiction["mutation_locality"]["changed_fields"] == [
        "/candidate/artifact_sha256",
        "/candidate/candidate_manifest_sha256",
        "/candidate/fresh_grade",
    ]
    assert contradiction["mutation_locality"]["favourability_payload_unchanged"] is False
    assert control["mutation_locality"]["favourability_payload_unchanged"] is True


def test_p2_stale_changes_only_the_evaluation_clock() -> None:
    records = {
        json.loads(path.read_text(encoding="utf-8"))["body"]["case_id"]: json.loads(
            path.read_text(encoding="utf-8")
        )["body"]
        for path in (PACKAGE_ROOT / "records" / "fixture-admissibility").glob("*.json")
    }
    stale = records["P2-02"]
    assert stale["mutation_locality"]["changed_fields"] == ["/fixed_clock"]


def test_secret_validator_detects_high_signal_token(tmp_path: Path) -> None:
    policy_root = tmp_path / "package"
    (policy_root / "policies").mkdir(parents=True)
    (policy_root / "fixtures").mkdir()
    (policy_root / "records" / "fixture-admissibility").mkdir(parents=True)
    policy = json.loads((PACKAGE_ROOT / "policies" / "secret-patterns-v1.json").read_text(encoding="utf-8"))
    (policy_root / "policies" / "secret-patterns-v1.json").write_text(json.dumps(policy), encoding="utf-8")
    (policy_root / "fixtures" / "fx-01.json").write_text('{"value":"AKIAABCDEFGHIJKLMNOP"}', encoding="utf-8")
    assert any("aws-access-key" in error for error in secret_errors(policy_root))


def test_contamination_validator_rejects_oracle_metadata(tmp_path: Path) -> None:
    policy_root = tmp_path / "package"
    (policy_root / "policies").mkdir(parents=True)
    (policy_root / "fixtures").mkdir()
    policy_path = PACKAGE_ROOT / "policies" / "privacy-locality-v1.json"
    (policy_root / "policies" / "privacy-locality-v1.json").write_bytes(policy_path.read_bytes())
    (policy_root / "fixtures" / "fx-01.json").write_text('{"authority_ceiling":"STRONG"}', encoding="utf-8")
    assert any("forbidden metadata keys" in error for error in privacy_contamination_errors(policy_root))


def test_secret_patterns_are_bounded_and_actual_fixtures_are_clean() -> None:
    assert secret_errors(PACKAGE_ROOT) == []
    policy = json.loads((PACKAGE_ROOT / "policies" / "secret-patterns-v1.json").read_text(encoding="utf-8"))
    assert all(re.compile(item["regex"]) for item in policy["patterns"])


def test_allowed_write_manifest_matches_every_package_file() -> None:
    assert allowed_write_errors(PACKAGE_ROOT) == []


def test_deterministic_regeneration_is_byte_identical() -> None:
    receipt, errors = deterministic_regeneration(PACKAGE_ROOT)
    assert errors == []
    assert receipt["byte_identical"] is True
    assert receipt["compared_files"] > 70


def test_no_record_self_certifies_independent_admission() -> None:
    records = [
        json.loads(path.read_text(encoding="utf-8")) for path in (PACKAGE_ROOT / "records").rglob("*.json")
    ]
    assert len(records) == 29
    assert {record["admission_status"] for record in records} == {"CANDIDATE"}
    assert all(record["reviews"] == [] for record in records)
    fixture_records = [record for record in records if record["schema"] == "FixtureAdmissibilityV1"]
    assert all(
        record["body"]["rights"]["reviewer"] == "PENDING_INDEPENDENT_REVIEW" for record in fixture_records
    )


@pytest.mark.parametrize("path_id", ["p1", "p2", "p3"])
def test_three_path_definitions_are_frozen(path_id: str) -> None:
    payload = json.loads((PACKAGE_ROOT / "paths" / f"{path_id}.json").read_text(encoding="utf-8"))
    assert payload["path_id"] == path_id.upper()
