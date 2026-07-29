"""Click commands for the offline MCP Tool Result Contract Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_cli import _write_artifacts
from mcp_audit.tool_result_models import ToolResultFixture, ToolResultReport
from mcp_audit.tool_result_scanner import (
    ToolResultInputError,
    report_json_bytes,
    scan_tool_result_path_with_identity,
)


class ToolResultUsageError(click.ClickException):
    exit_code = 2


@click.group("tool-result")
def tool_result() -> None:
    """Audit paired synthetic tools/list and tools/call evidence offline."""


@tool_result.command("scan")
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
@click.option("--force", is_flag=True, default=False, help="Replace an existing regular report file.")
def scan_command(fixture: Path, json_path: Path | None, force: bool) -> None:
    """Evaluate one program-owned transcript without connecting or executing."""
    try:
        report, input_identity = scan_tool_result_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        artifacts = [(json_path, json_bytes)] if json_path is not None else []
        _write_artifacts(fixture, input_identity, artifacts, force=force)
    except (ToolResultInputError, OSError, ValueError) as exc:
        raise ToolResultUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@tool_result.command("schema")
@click.argument("contract", type=click.Choice(["fixture", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict fixture-side JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "fixture": ToolResultFixture,
        "report": ToolResultReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
