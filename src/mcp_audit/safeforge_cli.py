"""CLI adapters for the SafeForge handoff and runtime pipeline."""

from __future__ import annotations

import json
from datetime import datetime
from functools import partial
from pathlib import Path

import anyio
import click

_MAX_SAFEFORGE_SCHEMA_BYTES = 1_048_576
_MAX_SAFEFORGE_RECEIPT_BYTES = 4_194_304


@click.command("safeforge-preinstall")
@click.option(
    "--producer-schema",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
    help="ForgeReceiptV0 JSON Schema exported by the producer.",
)
@click.option(
    "--receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
    help="ForgeReceiptV0 JSON receipt.",
)
@click.option(
    "--artifact-root",
    type=click.Path(path_type=Path),
    required=True,
    help="Generated artifact directory bound by the receipt.",
)
@click.option("--run-id", required=True, help="Portable SafeForge run identifier.")
@click.option("--created-at", required=True, help="Coordinator timestamp in RFC 3339 form.")
@click.option("--coordinator-revision", required=True, help="MCPAudit source revision.")
@click.option("--coordinator-dirty", is_flag=True, default=False, help="Mark coordinator tree dirty.")
def safeforge_preinstall(
    producer_schema: Path,
    receipt: Path,
    artifact_root: Path,
    run_id: str,
    created_at: str,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> None:
    """Verify a forge handoff and run config-only audit without execution."""
    from mcp_audit.safeforge_coordinator import run_safeforge_preinstall

    try:
        producer_payload = _load_safeforge_json(producer_schema, _MAX_SAFEFORGE_SCHEMA_BYTES)
        receipt_payload = _load_safeforge_json(receipt, _MAX_SAFEFORGE_RECEIPT_BYTES)
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if not isinstance(producer_payload, dict) or not isinstance(receipt_payload, dict):
            raise ValueError("producer schema and receipt must be JSON objects")
        if timestamp.tzinfo is None:
            raise ValueError("--created-at must include a timezone")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        click.echo(
            json.dumps(
                {
                    "accepted": False,
                    "error": {"code": "SF-INPUT-INVALID", "message": str(exc)},
                },
                sort_keys=True,
            )
        )
        raise click.exceptions.Exit(2) from None

    operation = partial(
        run_safeforge_preinstall,
        producer_payload,
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=timestamp,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    result = anyio.run(operation)
    click.echo(result.model_dump_json(exclude_none=True))
    if not result.accepted:
        raise click.exceptions.Exit(1)


@click.command("safeforge-run")
@click.option(
    "--producer-schema",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.option(
    "--receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.option("--artifact-root", type=click.Path(path_type=Path), required=True)
@click.option("--run-id", required=True)
@click.option("--created-at", required=True)
@click.option("--coordinator-revision", required=True)
@click.option("--coordinator-dirty", is_flag=True, default=False)
def safeforge_run(
    producer_schema: Path,
    receipt: Path,
    artifact_root: Path,
    run_id: str,
    created_at: str,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> None:
    """Verify, materialize, execute, audit, grade, and finalize in a disposable sandbox."""
    from mcp_audit.safeforge_runtime import run_safeforge_pipeline

    try:
        producer_payload = _load_safeforge_json(producer_schema, _MAX_SAFEFORGE_SCHEMA_BYTES)
        receipt_payload = _load_safeforge_json(receipt, _MAX_SAFEFORGE_RECEIPT_BYTES)
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if not isinstance(producer_payload, dict) or not isinstance(receipt_payload, dict):
            raise ValueError("producer schema and receipt must be JSON objects")
        if timestamp.tzinfo is None:
            raise ValueError("--created-at must include a timezone")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        click.echo(
            json.dumps(
                {"accepted": False, "error": {"code": "SF-INPUT-INVALID", "message": str(exc)}},
                sort_keys=True,
            )
        )
        raise click.exceptions.Exit(2) from None

    operation = partial(
        run_safeforge_pipeline,
        producer_payload,
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=timestamp,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    result = anyio.run(operation)
    click.echo(result.model_dump_json(exclude_none=True))
    if not result.accepted:
        raise click.exceptions.Exit(1)


def _load_safeforge_json(path: Path, maximum_bytes: int) -> object:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ValueError(f"{path.name} exceeds the {maximum_bytes}-byte input limit")
    return json.loads(path.read_text(encoding="utf-8"))
