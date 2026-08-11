"""Click commands for the experimental offline MCP Cache Contract Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.cache_contract_models import CacheAuditReport, CacheTrace
from mcp_audit.cache_contract_scanner import (
    CacheContractInputError,
    report_json_bytes,
    scan_cache_path,
)


class CacheContractUsageError(click.ClickException):
    exit_code = 2


@click.group("cache-contract")
def cache_contract() -> None:
    """Audit one bounded synthetic MCP cache trace offline."""


@cache_contract.command("scan")
@click.argument(
    "trace",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
def scan_command(trace: Path) -> None:
    """Emit one deterministic JSON cache-contract report."""

    try:
        report = scan_cache_path(trace)
    except (CacheContractInputError, OSError) as exc:
        raise CacheContractUsageError(str(exc)) from exc
    click.echo(report_json_bytes(report).decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@cache_contract.command("schema")
@click.argument("contract", type=click.Choice(["trace", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""

    models: dict[str, type[BaseModel]] = {
        "trace": CacheTrace,
        "report": CacheAuditReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
