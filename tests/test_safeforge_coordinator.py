"""Single-command SafeForge preinstall coordinator tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.safeforge_consumer import ForgeReceiptV0Input, SafeForgePreinstallResult
from mcp_audit.safeforge_coordinator import run_safeforge_preinstall

_NOW = datetime(2026, 7, 10, 18, 0, tzinfo=UTC)


async def test_contract_drift_blocks_before_artifact_or_consumer_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("receipt consumer must not run after contract drift")

    monkeypatch.setattr("mcp_audit.safeforge_coordinator.consume_forge_receipt", _forbidden)
    schema = ForgeReceiptV0Input.model_json_schema()
    schema["properties"]["new_optional_field"] = {"type": "string"}

    result = await run_safeforge_preinstall(
        schema,
        {},
        tmp_path / "does-not-exist",
        run_id="contract-drift",
        created_at=_NOW,
        coordinator_revision="audit-revision",
        coordinator_dirty=False,
    )

    assert not result.accepted
    assert result.preinstall is None
    assert result.contract.issues[0].change == "additive"


async def test_exact_contract_delegates_to_preinstall_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    async def _consume(*args: object, **kwargs: object) -> SafeForgePreinstallResult:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return SafeForgePreinstallResult(accepted=True)

    monkeypatch.setattr("mcp_audit.safeforge_coordinator.consume_forge_receipt", _consume)
    result = await run_safeforge_preinstall(
        ForgeReceiptV0Input.model_json_schema(),
        {"receipt_version": "0.1.0"},
        tmp_path,
        run_id="exact-contract",
        created_at=_NOW,
        coordinator_revision="audit-revision",
        coordinator_dirty=False,
    )

    assert result.accepted
    assert result.preinstall is not None
    assert observed["args"] == ({"receipt_version": "0.1.0"}, tmp_path)


def test_cli_invalid_json_returns_machine_readable_input_failure(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    receipt = tmp_path / "receipt.json"
    artifact_root = tmp_path / "artifact"
    schema.write_text("not-json", encoding="utf-8")
    receipt.write_text("{}", encoding="utf-8")
    artifact_root.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "safeforge-preinstall",
            "--producer-schema",
            str(schema),
            "--receipt",
            str(receipt),
            "--artifact-root",
            str(artifact_root),
            "--run-id",
            "invalid-input",
            "--created-at",
            _NOW.isoformat(),
            "--coordinator-revision",
            "audit-revision",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["accepted"] is False
    assert payload["error"]["code"] == "SF-INPUT-INVALID"


def test_cli_contract_drift_blocks_before_missing_artifact_access(tmp_path: Path) -> None:
    schema_payload = ForgeReceiptV0Input.model_json_schema()
    schema_payload["properties"]["new_optional_field"] = {"type": "string"}
    schema = tmp_path / "schema.json"
    receipt = tmp_path / "receipt.json"
    schema.write_text(json.dumps(schema_payload), encoding="utf-8")
    receipt.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "safeforge-preinstall",
            "--producer-schema",
            str(schema),
            "--receipt",
            str(receipt),
            "--artifact-root",
            str(tmp_path / "does-not-exist"),
            "--run-id",
            "contract-drift",
            "--created-at",
            _NOW.isoformat(),
            "--coordinator-revision",
            "audit-revision",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["accepted"] is False
    assert payload["contract"]["issues"][0]["change"] == "additive"
    assert "preinstall" not in payload


def test_cli_rejects_oversized_schema_with_structured_input_failure(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    receipt = tmp_path / "receipt.json"
    schema.write_text(json.dumps({"padding": "x" * 1_048_576}), encoding="utf-8")
    receipt.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "safeforge-preinstall",
            "--producer-schema",
            str(schema),
            "--receipt",
            str(receipt),
            "--artifact-root",
            str(tmp_path / "unused"),
            "--run-id",
            "oversized-schema",
            "--created-at",
            _NOW.isoformat(),
            "--coordinator-revision",
            "audit-revision",
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["error"]["code"] == "SF-INPUT-INVALID"
    assert "input limit" in payload["error"]["message"]
