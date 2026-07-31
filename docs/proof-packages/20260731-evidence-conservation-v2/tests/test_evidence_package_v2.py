"""Focused offline tests for the v2 evidence-package candidate."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from package_lib import (  # noqa: E402
    PACKAGE_ID,
    STATIC_RELATIVE_PATHS,
    build_package,
    near_miss_boundaries,
    tar_members,
    validate_package,
)


def test_full_package_validation_passes() -> None:
    result = validate_package(ROOT, jsonschema)
    assert result["status"] == "PASS", result["errors"]
    assert result["file_count"] == 100
    assert result["fixture_count"] == 21
    assert result["record_count"] == 29
    assert result["schema_count"] == 19


def test_primary_and_boundary_counts_are_exact() -> None:
    summary = json.loads((ROOT / "admission-summary.json").read_text())
    assert summary["primary_corpus"] == {"controls": 3, "mutations": 18, "total": 21}
    assert summary["boundaries"] == {"no_op": 6, "near_miss": 6}
    assert summary["coverage"] == {"covered": 11, "partial": 6, "cross": 1}
    assert summary["record_counts"]["total"] == 29
    assert summary["runtime_execution"]["cases_executed"] == 0


def test_p3_06_changes_only_native_database_mode() -> None:
    import base64

    control = json.loads((ROOT / "fixtures/p3-control.json").read_text())
    mode_case = json.loads((ROOT / "fixtures/p3-06.json").read_text())

    def artifact(fixture: dict, name: str) -> bytes:
        row = next(item for item in fixture["artifacts"] if item["name"] == name)
        return base64.b64decode(row["content_base64"])

    assert artifact(control, "source.sqlite") == artifact(mode_case, "source.sqlite")
    before = tar_members(artifact(control, "recovery-anchor.tar"))
    after = tar_members(artifact(mode_case, "recovery-anchor.tar"))
    assert before["anchor.sqlite"][0] == after["anchor.sqlite"][0]
    assert before["anchor.json"][0] == after["anchor.json"][0]
    assert before["anchor.sqlite"][1] == 0o600
    assert after["anchor.sqlite"][1] == 0o644
    assert mode_case["expected"]["raw_signal"]["source_current"] == "ABSENT"


def test_unexpected_sidecar_boundary_is_fixed_and_non_primary() -> None:
    import base64

    near = near_miss_boundaries()
    sidecar = near["entries"][5]
    assert sidecar["boundary_id"] == "NEAR-06"
    assert base64.b64decode(sidecar["outside_artifact"]["content_base64"]) == b"untracked"
    assert sidecar["outside_reason"] == "anchor_artifact_set_mismatch"
    fixture_ids = {json.loads(path.read_text())["fixture_id"] for path in (ROOT / "fixtures").glob("*.json")}
    assert "NEAR-06" not in fixture_ids


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
    for relative in original_files:
        assert (ROOT / relative).read_bytes() == (regenerated / relative).read_bytes(), relative
