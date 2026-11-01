"""Acceptance checks for relocated lab tooling and CI selectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.generate_enforcement_schemas import SCHEMAS, main

ROOT = Path(__file__).resolve().parents[2]


def test_enforcement_schema_generator_preserves_checked_in_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = {name: (ROOT / "examples/schemas" / name).read_bytes() for name in SCHEMAS}
    monkeypatch.chdir(tmp_path)
    main()
    assert {path.name: path.read_bytes() for path in Path("examples/schemas").glob("*.json")} == expected


def test_safeforge_ci_selects_relocated_tests_and_installs_labs() -> None:
    workflow = (ROOT / ".github/workflows/macos-safeforge.yml").read_text()
    assert "uv sync --all-packages --dev --locked" in workflow
    assert "tests/test_safeforge" not in workflow
    for name in (
        "test_supervisor_kills_hanging_shutdown_resistant_process_group",
        "test_supervisor_enforces_process_count",
        "test_supervisor_enforces_memory_and_disk",
        "test_kernel_denies_artifact_root_escape_and_network",
        "test_generated_code_profile_kernel_denies_child_processes",
    ):
        assert workflow.count(f"tests/labs/test_safeforge_runtime.py::{name}") == 2
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert ci.count("--cov=mcp_audit --cov=mcp_audit_labs ") == 2
