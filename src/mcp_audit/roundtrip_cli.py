"""Click commands for the offline MCP 2026 stateless round-trip auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_cli import _write_artifacts
from mcp_audit.roundtrip_models import (
    RequestStateWitness,
    RoundTripJsonlManifest,
    RoundTripReport,
    RoundTripTrace,
)
from mcp_audit.roundtrip_scanner import (
    RoundTripInputError,
    canonical_json_bytes,
    report_json_bytes,
    scan_roundtrip_path_with_identity,
)
from mcp_audit.sarif import SarifGenerator


class RoundTripUsageError(click.ClickException):
    """Safe input/output error with the documented exit status."""

    exit_code = 2


@click.group("roundtrip")
def roundtrip() -> None:
    """Audit program-owned MCP 2026 JSON or JSONL exchanges offline."""


@roundtrip.command("scan")
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
    help="Write a SARIF 2.1.0 compatibility projection.",
)
@click.option("--force", is_flag=True, default=False, help="Replace existing regular report files.")
def scan_command(
    fixture: Path,
    json_path: Path | None,
    sarif_path: Path | None,
    force: bool,
) -> None:
    """Scan one synthetic trace without connecting, executing, or discovering."""
    try:
        report, input_identity = scan_roundtrip_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        sarif_bytes = (
            canonical_json_bytes(SarifGenerator().generate_roundtrip(report))
            if sarif_path is not None
            else None
        )
        artifacts = [
            item
            for item in (
                (json_path, json_bytes) if json_path is not None else None,
                (sarif_path, sarif_bytes) if sarif_path is not None and sarif_bytes is not None else None,
            )
            if item is not None
        ]
        _write_artifacts(fixture, input_identity, artifacts, force=force)
    except (RoundTripInputError, OSError, ValueError) as exc:
        raise RoundTripUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@roundtrip.command("schema")
@click.argument(
    "contract",
    type=click.Choice(["trace", "jsonl-manifest", "request-state-witness", "report"]),
)
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "trace": RoundTripTrace,
        "jsonl-manifest": RoundTripJsonlManifest,
        "request-state-witness": RequestStateWitness,
        "report": RoundTripReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), separators=(",", ":"), sort_keys=True))
