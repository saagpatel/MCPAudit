"""Click commands for the offline MCP OAuth transcript auditor."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_cli import _write_artifacts
from mcp_audit.oauth_transcript_models import OAuthTranscriptFixture, OAuthTranscriptReport
from mcp_audit.oauth_transcript_sarif import oauth_report_to_sarif
from mcp_audit.oauth_transcript_scanner import (
    OAuthTranscriptInputError,
    report_json_bytes,
    scan_oauth_transcript_path_with_identity,
)


class OAuthTranscriptUsageError(click.ClickException):
    exit_code = 2


@click.group("oauth-transcript")
def oauth_transcript() -> None:
    """Audit one explicitly synthetic, redacted MCP OAuth transcript offline."""


@oauth_transcript.command("scan")
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
    help="Write the SARIF 2.1.0 compatibility projection.",
)
@click.option("--force", is_flag=True, default=False, help="Replace existing regular report files.")
def scan_command(
    fixture: Path,
    json_path: Path | None,
    sarif_path: Path | None,
    force: bool,
) -> None:
    """Evaluate observable bindings without connecting, authenticating, or fetching."""
    try:
        report, input_identity = scan_oauth_transcript_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        sarif_bytes = (
            json.dumps(
                oauth_report_to_sarif(report),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode()
        artifacts = [
            item
            for item in (
                (json_path, json_bytes) if json_path is not None else None,
                (sarif_path, sarif_bytes) if sarif_path is not None else None,
            )
            if item is not None
        ]
        _write_artifacts(fixture, input_identity, artifacts, force=force)
    except (OAuthTranscriptInputError, OSError, ValueError) as exc:
        raise OAuthTranscriptUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@oauth_transcript.command("schema")
@click.argument("contract", type=click.Choice(["fixture", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "fixture": OAuthTranscriptFixture,
        "report": OAuthTranscriptReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
