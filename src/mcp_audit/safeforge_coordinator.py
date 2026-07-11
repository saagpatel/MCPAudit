"""Single read-only coordinator for the SafeForge preinstall handoff."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_audit.safeforge_consumer import SafeForgePreinstallResult, consume_forge_receipt
from mcp_audit.safeforge_contract_linter import ForgeReceiptContractLint, lint_forge_receipt_schema


class SafeForgeCoordinatorResult(BaseModel):
    """Machine-readable result for the complete preinstall boundary."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool
    contract: ForgeReceiptContractLint
    preinstall: SafeForgePreinstallResult | None = None


async def run_safeforge_preinstall(
    producer_schema: dict[str, Any],
    receipt_payload: Mapping[str, Any],
    artifact_root: Path,
    *,
    run_id: str,
    created_at: datetime,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> SafeForgeCoordinatorResult:
    """Lint the producer contract, then verify and audit without execution."""
    contract = lint_forge_receipt_schema(producer_schema)
    if not contract.compatible:
        return SafeForgeCoordinatorResult(accepted=False, contract=contract)

    preinstall = await consume_forge_receipt(
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=created_at,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    return SafeForgeCoordinatorResult(
        accepted=preinstall.accepted,
        contract=contract,
        preinstall=preinstall,
    )
