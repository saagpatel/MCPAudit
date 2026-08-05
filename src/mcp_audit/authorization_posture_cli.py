"""Click commands for offline authorization-posture adoption."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_cli import _write_artifacts
from mcp_audit.authorization_posture_models import (
    AuthorizationPostureReport,
    McpAuthorizationPostureV1,
)
from mcp_audit.authorization_posture_scanner import (
    AuthorizationPostureInputError,
    report_json_bytes,
    review_authorization_posture_path_with_identity,
)


class AuthorizationPostureUsageError(click.ClickException):
    exit_code = 2


@click.group("authorization-posture")
def authorization_posture() -> None:
    """Review one saved McpAuthorizationPostureV1 artifact offline."""


@authorization_posture.command("review")
@click.argument(
    "posture",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--json",
    "json_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the canonical machine-readable advisory report.",
)
@click.option("--force", is_flag=True, default=False, help="Replace an existing regular report file.")
def review_command(posture: Path, json_path: Path | None, force: bool) -> None:
    """Validate and project posture without fetching, authenticating, or scanning."""
    usage_error: str | None = None
    try:
        report, input_identity = review_authorization_posture_path_with_identity(posture)
        json_bytes = report_json_bytes(report)
        artifacts = [] if json_path is None else [(json_path, json_bytes)]
        _write_artifacts(posture, input_identity, artifacts, force=force)
    except (AuthorizationPostureInputError, OSError, ValueError) as exc:
        usage_error = str(exc)
    if usage_error is not None:
        raise AuthorizationPostureUsageError(usage_error)
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.disposition != "policy-review-only":
        raise click.exceptions.Exit(1)


@authorization_posture.command("schema")
@click.argument("contract", type=click.Choice(["input", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "input": McpAuthorizationPostureV1,
        "report": AuthorizationPostureReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
