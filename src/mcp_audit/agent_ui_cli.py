"""Click commands for the experimental offline Agent UI Contract Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit._artifacts import _write_artifacts
from mcp_audit.agent_ui_models import (
    A2UIFixtureManifest,
    A2UIMessage,
    AgentUIReport,
    MCPAppsFixture,
)
from mcp_audit.agent_ui_scanner import (
    AgentUIInputError,
    render_agent_ui_html,
    report_json_bytes,
    scan_agent_ui_path_with_identity,
)


class AgentUIUsageError(click.ClickException):
    exit_code = 2


@click.group("agent-ui")
def agent_ui() -> None:
    """Audit program-owned MCP Apps metadata and A2UI JSONL fixtures offline."""


@agent_ui.command("scan")
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
    "--html",
    "html_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the inert offline HTML projection.",
)
@click.option("--force", is_flag=True, default=False, help="Replace existing regular report files.")
def scan_command(
    fixture: Path,
    json_path: Path | None,
    html_path: Path | None,
    force: bool,
) -> None:
    """Statically scan one synthetic fixture without executing or connecting."""
    try:
        report, input_identity = scan_agent_ui_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        html_bytes = render_agent_ui_html(report).encode("utf-8")
        artifacts = [
            item
            for item in (
                (json_path, json_bytes) if json_path is not None else None,
                (html_path, html_bytes) if html_path is not None else None,
            )
            if item is not None
        ]
        _write_artifacts(fixture, input_identity, artifacts, force=force)
    except (AgentUIInputError, OSError, ValueError) as exc:
        raise AgentUIUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@agent_ui.command("schema")
@click.argument(
    "contract",
    type=click.Choice(
        [
            "mcp-apps-fixture",
            "a2ui-fixture-manifest",
            "a2ui-message",
            "report",
        ]
    ),
)
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "mcp-apps-fixture": MCPAppsFixture,
        "a2ui-fixture-manifest": A2UIFixtureManifest,
        "a2ui-message": A2UIMessage,
        "report": AgentUIReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
