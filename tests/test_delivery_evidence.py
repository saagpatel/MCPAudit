"""Tests for the bounded delivery-evidence validator."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_delivery_evidence.py"
SPEC = importlib.util.spec_from_file_location("validate_delivery_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
ENVIRONMENT = "sha256:" + "c" * 64


def _document() -> dict[str, Any]:
    return {
        "schema_version": "mcpaudit.delivery-evidence.v1",
        "artifact": {
            "repository": "saagpatel/MCPAudit",
            "revision": REVISION,
            "source_sha256": DIGEST,
            "environment_required": True,
            "environment_sha256": ENVIRONMENT,
        },
        "producer": {"name": "fixture-producer", "produced_at": "2026-08-13T22:59:00Z"},
        "freshness": {"as_of": "2026-08-13T23:00:00Z", "current_state_max_age_seconds": 300},
        "repository_policy": {"delete_branch_on_merge": True},
        "integration": {
            "protected_main": {"revision": REVISION, "reachable": True},
            "pull_request": {
                "number": 212,
                "state": "merged",
                "head_revision": REVISION,
                "integration_revision": REVISION,
            },
            "review": {"revision": REVISION, "status": "PASS", "unresolved_threads": 0},
            "security": {"revision": REVISION, "source_sha256": DIGEST, "status": "PASS"},
            "ci": [
                {
                    "name": "test (3.13)",
                    "revision": REVISION,
                    "status": "PASS",
                    "environment_sha256": ENVIRONMENT,
                }
            ],
        },
        "branch": {
            "evidence_class": "mutable_convenience",
            "ref": "refs/heads/codex/example",
            "state": "absent",
            "observed_at": "2026-08-13T22:59:30Z",
            "revision": None,
        },
        "retention": {
            "required": False,
            "reason": None,
            "consumer": None,
            "lifecycle": None,
            "mutation_authority": None,
            "deletion_policy": None,
            "exception_path": "none",
        },
        "claims": [
            {
                "boundary": "source",
                "status": "PASS",
                "evidence_boundaries": ["source"],
                "current_state": False,
                "observed_at": "2026-08-13T22:58:00Z",
            },
            {
                "boundary": "ci",
                "status": "PASS",
                "evidence_boundaries": ["ci"],
                "current_state": False,
                "observed_at": "2026-08-13T22:58:00Z",
            },
        ],
        "claim_ceiling": {
            "proven_boundaries": ["source", "ci"],
            "unproven_boundaries": [
                "local",
                "runtime",
                "publication",
                "deployment",
                "adoption",
                "human_acceptance",
            ],
            "statement": "source and exact-SHA CI only",
        },
    }


def _codes(result: dict[str, Any]) -> set[str]:
    return {finding["code"] for finding in result["findings"]}


def test_merged_evidence_remains_valid_when_branch_is_absent() -> None:
    assert validator.validate(_document())["verdict"] == "PASS"


def test_exact_live_branch_is_valid_optional_pointer() -> None:
    document = _document()
    document["branch"].update(state="present", revision=REVISION)
    assert validator.validate(document)["verdict"] == "PASS"


@pytest.mark.parametrize("reachable", [0, 1, "false", "true"])
def test_protected_main_reachability_rejects_non_boolean_values(reachable: Any) -> None:
    document = _document()
    document["integration"]["protected_main"]["reachable"] = reachable
    with pytest.raises(validator.DeliveryEvidenceInputError, match="boolean or null"):
        validator.validate(document)


@pytest.mark.parametrize(
    ("reachable", "verdict"),
    [(True, "PASS"), (False, "FAIL"), (None, "UNKNOWN")],
)
def test_protected_main_reachability_preserves_tristate_semantics(
    reachable: bool | None, verdict: str
) -> None:
    document = _document()
    document["integration"]["protected_main"]["reachable"] = reachable
    assert validator.validate(document)["verdict"] == verdict


def test_wrong_live_branch_revision_fails() -> None:
    document = _document()
    document["branch"].update(state="present", revision="d" * 40)
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY001" in _codes(result)


def _require_retention(document: dict[str, Any], exception: str) -> None:
    document["retention"] = {
        "required": True,
        "reason": "named downstream consumer",
        "consumer": "compatibility receipt importer",
        "lifecycle": "until importer migration completes",
        "mutation_authority": "repository maintainer",
        "deletion_policy": "one bounded policy effect",
        "exception_path": exception,
    }


def test_automatic_deletion_contradicts_unconditional_retention() -> None:
    document = _document()
    _require_retention(document, "none")
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY010" in _codes(result)


def test_bounded_restoration_is_structural_but_needs_live_readback() -> None:
    document = _document()
    _require_retention(document, "bounded_post_merge_restoration")
    result = validator.validate(document)
    assert result["verdict"] == "UNKNOWN"
    assert _codes(result) == {"MCPDELIVERY011"}


def test_optional_unknown_branch_state_stays_unknown() -> None:
    document = _document()
    document["branch"]["state"] = "unknown"
    result = validator.validate(document)
    assert result["verdict"] == "UNKNOWN"
    assert _codes(result) == {"MCPDELIVERY014"}


def test_required_retention_with_unknown_branch_state_stays_unknown() -> None:
    document = _document()
    document["branch"]["state"] = "unknown"
    _require_retention(document, "bounded_post_merge_restoration")
    result = validator.validate(document)
    assert result["verdict"] == "UNKNOWN"
    assert _codes(result) == {"MCPDELIVERY011", "MCPDELIVERY014"}


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("revision", "d" * 40, "MCPDELIVERY002"),
        ("source_sha256", "sha256:" + "d" * 64, "MCPDELIVERY003"),
    ],
)
def test_cross_artifact_receipt_reuse_fails(field: str, value: str, code: str) -> None:
    document = _document()
    document["integration"]["security"][field] = value
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert code in _codes(result)


def test_missing_required_environment_binding_is_unknown() -> None:
    document = _document()
    document["artifact"]["environment_sha256"] = None
    document["integration"]["ci"][0]["environment_sha256"] = None
    result = validator.validate(document)
    assert result["verdict"] == "UNKNOWN"
    assert "MCPDELIVERY008" in _codes(result)


def test_supplied_optional_environment_mismatch_fails() -> None:
    document = _document()
    document["artifact"]["environment_required"] = False
    document["integration"]["ci"][0]["environment_sha256"] = "sha256:" + "d" * 64
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY008" in _codes(result)


def test_stale_current_state_claim_fails() -> None:
    document = _document()
    document["claims"].append(
        {
            "boundary": "publication",
            "status": "PASS",
            "evidence_boundaries": ["publication"],
            "current_state": True,
            "observed_at": "2026-08-13T20:00:00Z",
        }
    )
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY009" in _codes(result)
    assert "publication" not in result["claim_ceiling"]["proven_boundaries"]
    assert "publication" in result["claim_ceiling"]["unproven_boundaries"]


def test_future_historical_claim_fails() -> None:
    document = _document()
    document["claims"][0]["observed_at"] = "2099-01-01T00:00:00Z"
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY009" in _codes(result)
    assert "source" not in result["claim_ceiling"]["proven_boundaries"]
    assert "source" in result["claim_ceiling"]["unproven_boundaries"]


@pytest.mark.parametrize(
    "value",
    ["2026-W33-4T23:00:00Z", "20260813T230000Z", "2026-08-13 23:00:00Z"],
)
def test_non_rfc3339_timestamp_shapes_are_rejected(value: str) -> None:
    document = _document()
    document["freshness"]["as_of"] = value
    with pytest.raises(validator.DeliveryEvidenceInputError):
        validator.validate(document)


def test_claim_ceiling_must_exactly_match_passing_boundaries() -> None:
    document = _document()
    document["claim_ceiling"]["proven_boundaries"].append("runtime")
    document["claim_ceiling"]["unproven_boundaries"].remove("runtime")
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY013" in _codes(result)


@pytest.mark.parametrize(
    ("boundary", "support"),
    [
        ("runtime", "publication"),
        ("publication", "runtime"),
        ("deployment", "publication"),
        ("adoption", "deployment"),
        ("human_acceptance", "adoption"),
    ],
)
def test_passing_claim_requires_evidence_from_its_own_boundary(boundary: str, support: str) -> None:
    document = _document()
    document["claims"].append(
        {
            "boundary": boundary,
            "status": "PASS",
            "evidence_boundaries": [support],
            "current_state": False,
            "observed_at": None,
        }
    )
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY012" in _codes(result)
    assert boundary not in result["claim_ceiling"]["proven_boundaries"]
    assert boundary in result["claim_ceiling"]["unproven_boundaries"]


@pytest.mark.parametrize("boundary", ["runtime", "publication", "deployment", "adoption", "human_acceptance"])
def test_higher_boundary_cannot_be_inferred_from_source_or_ci(boundary: str) -> None:
    document = _document()
    document["claims"].append(
        {
            "boundary": boundary,
            "status": "PASS",
            "evidence_boundaries": ["source", "ci"],
            "current_state": False,
            "observed_at": None,
        }
    )
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "MCPDELIVERY012" in _codes(result)


def test_invalid_claim_does_not_remove_independent_valid_claims() -> None:
    document = _document()
    document["claims"].append(
        {
            "boundary": "runtime",
            "status": "PASS",
            "evidence_boundaries": ["publication"],
            "current_state": False,
            "observed_at": None,
        }
    )
    document["claim_ceiling"]["proven_boundaries"].append("runtime")
    document["claim_ceiling"]["unproven_boundaries"].remove("runtime")
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert result["claim_ceiling"]["proven_boundaries"] == ["source", "ci"]
    assert "runtime" in result["claim_ceiling"]["unproven_boundaries"]


def test_every_valid_boundary_can_remain_in_effective_ceiling() -> None:
    document = _document()
    for boundary in validator.BOUNDARIES:
        if boundary in {"source", "ci"}:
            continue
        document["claims"].append(
            {
                "boundary": boundary,
                "status": "PASS",
                "evidence_boundaries": [boundary],
                "current_state": False,
                "observed_at": None,
            }
        )
    document["claim_ceiling"]["proven_boundaries"] = list(validator.BOUNDARIES)
    document["claim_ceiling"]["unproven_boundaries"] = []
    result = validator.validate(document)
    assert result["verdict"] == "PASS"
    assert result["claim_ceiling"]["proven_boundaries"] == list(validator.BOUNDARIES)
    assert result["claim_ceiling"]["unproven_boundaries"] == []


@pytest.mark.parametrize("ci_status", ["FAIL", "UNKNOWN"])
def test_nonpassing_ci_receipt_lowers_emitted_claim_ceiling(ci_status: str) -> None:
    document = _document()
    document["integration"]["ci"][0]["status"] = ci_status
    result = validator.validate(document)
    assert result["verdict"] == ci_status
    assert "ci" not in result["claim_ceiling"]["proven_boundaries"]
    assert "ci" in result["claim_ceiling"]["unproven_boundaries"]
    assert "MCPDELIVERY007" in _codes(result)


def test_mixed_ci_receipts_lower_emitted_claim_ceiling() -> None:
    document = _document()
    document["integration"]["ci"].append(
        {
            "name": "test (3.12)",
            "revision": REVISION,
            "status": "FAIL",
            "environment_sha256": ENVIRONMENT,
        }
    )
    result = validator.validate(document)
    assert result["verdict"] == "FAIL"
    assert "ci" not in result["claim_ceiling"]["proven_boundaries"]
    assert "ci" in result["claim_ceiling"]["unproven_boundaries"]
    assert "MCPDELIVERY007" in _codes(result)


def test_output_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    first = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    second = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


@pytest.mark.parametrize(
    "raw",
    [
        b"{not json}",
        b'{"schema_version":"one","schema_version":"two"}',
        (b"[" * 2_000) + b"0" + (b"]" * 2_000),
        b'{"number":' + (b"9" * 5_000) + b"}",
        b'{"number":NaN}',
    ],
)
def test_malformed_or_duplicate_key_input_fails_closed(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["verdict"] == "FAIL"
    assert result.stderr == b""


@pytest.mark.parametrize("value", ["\ud800", "\udc00", "\udc00\ud800"])
def test_unpaired_or_reversed_surrogates_fail_structurally_without_traceback(
    tmp_path: Path, value: str
) -> None:
    document = _document()
    document["producer"]["name"] = value
    path = tmp_path / "bad-surrogate.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["verdict"] == "FAIL"
    assert result.stderr == b""
    assert b"Traceback" not in result.stdout + result.stderr


def test_surrogate_in_nested_boundary_array_fails_structurally(tmp_path: Path) -> None:
    document = _document()
    document["claim_ceiling"]["proven_boundaries"][0] = "\ud800"
    path = tmp_path / "nested-surrogate.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["verdict"] == "FAIL"
    assert result.stderr == b""


@pytest.mark.parametrize(
    "raw",
    [
        b'{"\\ud800": 1}',
        b'{"\\ud800": 1, "\\ud800": 2}',
        b'{"\\ud83d\\ude80": 1, "\xf0\x9f\x9a\x80": 2}',
    ],
)
def test_surrogate_object_keys_fail_structurally_without_traceback(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "surrogate-key.json"
    path.write_bytes(raw)
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["verdict"] == "FAIL"
    assert result.stderr == b""
    assert b"Traceback" not in result.stdout + result.stderr


def test_valid_surrogate_pair_and_decoded_non_bmp_are_canonically_equivalent(tmp_path: Path) -> None:
    digests: list[str] = []
    for index, value in enumerate(("\ud83d\ude80", "🚀")):
        document = _document()
        document["producer"]["name"] = value
        path = tmp_path / f"valid-unicode-{index}.json"
        path.write_text(json.dumps(document, ensure_ascii=index == 0), encoding="utf-8")
        result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
        assert result.returncode == 0
        assert result.stderr == b""
        digests.append(json.loads(result.stdout)["input_sha256"])
    assert digests[0] == digests[1]


def test_valid_multilingual_unicode_is_preserved(tmp_path: Path) -> None:
    document = _document()
    document["producer"]["name"] = "検証-مرحبا-🚀"
    path = tmp_path / "valid-multilingual.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 0
    assert result.stderr == b""
    assert json.loads(result.stdout)["verdict"] == "PASS"


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    target.write_text(json.dumps(_document()), encoding="utf-8")
    link = tmp_path / "receipt-link.json"
    link.symlink_to(target)
    result = subprocess.run([sys.executable, str(SCRIPT), str(link)], check=False, capture_output=True)
    assert result.returncode == 2
    assert "non-symlink" in json.loads(result.stdout)["error"]


def test_regular_file_is_supported_without_optional_open_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    monkeypatch.delattr(validator.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(validator.os, "O_NONBLOCK", raising=False)
    assert validator.load_and_validate(path)["verdict"] == "PASS"


def test_same_inode_metadata_change_during_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    actual_fstat = validator.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> Any:
        nonlocal calls
        calls += 1
        observed = actual_fstat(descriptor)
        if calls == 1:
            return observed
        return SimpleNamespace(
            st_mode=observed.st_mode,
            st_dev=observed.st_dev,
            st_ino=observed.st_ino,
            st_size=observed.st_size,
            st_mtime_ns=observed.st_mtime_ns + 1,
        )

    monkeypatch.setattr(validator.os, "fstat", changing_fstat)
    with pytest.raises(validator.DeliveryEvidenceInputError, match="changed during read"):
        validator.load_and_validate(path)


def test_contract_document_and_contributor_link_exist() -> None:
    root = Path(__file__).parents[1]
    contract = root / "docs" / "DELIVERY-EVIDENCE-CONTRACT.md"
    assert "MCPDELIVERY012" in contract.read_text(encoding="utf-8")
    assert "docs/DELIVERY-EVIDENCE-CONTRACT.md" in (root / "CONTRIBUTING.md").read_text(encoding="utf-8")
