"""Tests for the bounded delivery-evidence validator."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
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
        "claim_ceiling": "source and exact-SHA CI only",
    }


def _codes(result: dict[str, Any]) -> set[str]:
    return {finding["code"] for finding in result["findings"]}


def test_merged_evidence_remains_valid_when_branch_is_absent() -> None:
    assert validator.validate(_document())["verdict"] == "PASS"


def test_exact_live_branch_is_valid_optional_pointer() -> None:
    document = _document()
    document["branch"].update(state="present", revision=REVISION)
    assert validator.validate(document)["verdict"] == "PASS"


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


def test_output_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    first = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    second = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


@pytest.mark.parametrize("raw", [b"{not json}", b'{"schema_version":"one","schema_version":"two"}'])
def test_malformed_or_duplicate_key_input_fails_closed(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    result = subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False, capture_output=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["verdict"] == "FAIL"


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    target.write_text(json.dumps(_document()), encoding="utf-8")
    link = tmp_path / "receipt-link.json"
    link.symlink_to(target)
    result = subprocess.run([sys.executable, str(SCRIPT), str(link)], check=False, capture_output=True)
    assert result.returncode == 2
    assert "non-symlink" in json.loads(result.stdout)["error"]


def test_contract_document_and_contributor_link_exist() -> None:
    root = Path(__file__).parents[1]
    contract = root / "docs" / "DELIVERY-EVIDENCE-CONTRACT.md"
    assert "MCPDELIVERY012" in contract.read_text(encoding="utf-8")
    assert "docs/DELIVERY-EVIDENCE-CONTRACT.md" in (root / "CONTRIBUTING.md").read_text(encoding="utf-8")
