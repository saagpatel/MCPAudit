"""Click command for static offline skill and MCP-bundle scanning."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from mcp_audit.skillscan import SkillscanInputError, scan_path
from mcp_audit.skillscan_models import SkillscanReport, report_json_bytes

console = Console()


class SkillscanUsageError(click.ClickException):
    """A skillscan input or output path could not be handled safely."""

    exit_code = 1


def _write_report(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        try:
            existing = path.lstat()
        except OSError as exc:
            raise SkillscanInputError("cannot inspect JSON output path") from exc
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
            raise SkillscanInputError("JSON output must be a regular non-symlink file")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SkillscanInputError("cannot write JSON report") from exc


def _render_report(report: SkillscanReport) -> None:
    table = Table(title=f"Skillscan — {report.subject.name}")
    table.add_column("Check", style="cyan")
    table.add_column("Result")
    table.add_column("Findings", justify="right")
    for check in report.checks:
        style = {"pass": "green", "fail": "red", "error": "yellow"}[check.result]
        table.add_row(check.id, f"[{style}]{check.result}[/{style}]", str(check.findings))
    console.print(table)


@click.command("skillscan")
@click.argument("path", type=click.Path(path_type=Path))
@click.option("--name", help="Override the deterministic subject name.")
@click.option(
    "--json-out",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write skillscan-report/v1 JSON with a trailing newline.",
)
def skillscan(path: Path, name: str | None, json_out: Path | None) -> None:
    """Statically scan a skill directory or .mcpb/.zip bundle offline."""
    try:
        report = scan_path(path, name=name)
        if json_out is not None:
            _write_report(json_out, report_json_bytes(report))
    except (OSError, SkillscanInputError, ValueError) as exc:
        raise SkillscanUsageError(str(exc)) from None
    _render_report(report)
    if any(check.result == "fail" for check in report.checks):
        raise click.exceptions.Exit(2)
    if any(check.result == "error" for check in report.checks):
        raise click.exceptions.Exit(1)
