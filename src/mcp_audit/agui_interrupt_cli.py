"""Click commands for the offline AG-UI interrupt integrity auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_cli import write_offline_artifacts
from mcp_audit.agui_interrupt_models import (
    AGUIInterruptReport,
    EventRecord,
    FixtureManifest,
    RunInputProjection,
)
from mcp_audit.agui_interrupt_scanner import (
    AGUIInterruptInputError,
    report_json_bytes,
    sarif_json_bytes,
    scan_agui_interrupt_path_with_identity,
)


class AGUIInterruptUsageError(click.ClickException):
    exit_code = 2


@click.group("ag-ui-interrupt")
def agui_interrupt() -> None:
    """Audit synthetic AG-UI interrupt/resume transcripts offline."""


@agui_interrupt.command("scan")
@click.argument(
    "fixture",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--json",
    "json_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the canonical machine-readable report.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write a deterministic SARIF 2.1.0 projection.",
)
@click.option("--force", is_flag=True, default=False, help="Replace existing regular report files.")
def scan_command(
    fixture: Path,
    json_path: Path | None,
    sarif_path: Path | None,
    force: bool,
) -> None:
    """Reduce one program-owned transcript without running an agent or workflow."""
    try:
        report, input_identity = scan_agui_interrupt_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        sarif_bytes = sarif_json_bytes(report)
        artifacts = [
            item
            for item in (
                (json_path, json_bytes) if json_path is not None else None,
                (sarif_path, sarif_bytes) if sarif_path is not None else None,
            )
            if item is not None
        ]
        write_offline_artifacts(fixture, input_identity, artifacts, force=force)
    except (AGUIInterruptInputError, OSError, ValueError) as exc:
        raise AGUIInterruptUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@agui_interrupt.command("schema")
@click.argument(
    "contract",
    type=click.Choice(["fixture-manifest", "run-input", "event-record", "report"]),
)
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "fixture-manifest": FixtureManifest,
        "run-input": RunInputProjection,
        "event-record": EventRecord,
        "report": AGUIInterruptReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
