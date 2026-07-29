"""Offline CLI for synthetic MCP subscription stream traces."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.subscription_stream_models import SubscriptionReport, SubscriptionTrace
from mcp_audit.subscription_stream_scanner import (
    SubscriptionStreamInputError,
    report_json_bytes,
    report_sarif_bytes,
    scan_subscription_stream_path,
)


class SubscriptionStreamUsageError(click.ClickException):
    exit_code = 2


@click.group("subscription-stream")
def subscription_stream() -> None:
    """Audit program-owned MCP 2026 subscription stream traces offline."""


@subscription_stream.command("scan")
@click.argument(
    "fixture",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif"], case_sensitive=True),
    default="json",
    show_default=True,
    help="Canonical stdout format.",
)
def scan_command(fixture: Path, output_format: str) -> None:
    """Scan one bounded JSON trace without connecting to an MCP endpoint."""
    try:
        report = scan_subscription_stream_path(fixture)
    except (OSError, SubscriptionStreamInputError) as exc:
        raise SubscriptionStreamUsageError(str(exc)) from exc
    output = report_json_bytes(report) if output_format == "json" else report_sarif_bytes(report)
    click.echo(output.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@subscription_stream.command("schema")
@click.argument("contract", type=click.Choice(["trace", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "trace": SubscriptionTrace,
        "report": SubscriptionReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
