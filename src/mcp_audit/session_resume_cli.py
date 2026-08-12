"""CLI for the offline MCP Streamable HTTP session/resume fault lab."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import click
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from mcp_audit.session_resume_lab import (
    SessionResumeInputError,
    load_builtin_scenarios,
    load_scenario_path,
    report_json_bytes,
    run_builtin_suite,
    run_scenario,
)
from mcp_audit.session_resume_models import (
    SessionResumeReport,
    SessionResumeScenario,
    SessionResumeSuiteReport,
    SessionResumeTranscript,
)

console = Console()


class SessionResumeUsageError(click.ClickException):
    exit_code = 2


@click.group("session-resume")
def session_resume() -> None:
    """Replay deterministic MCP transport-session and resumability faults offline."""


@session_resume.command("list")
@click.option("--json", "json_output", is_flag=True, help="Emit the built-in scenario index as JSON.")
def list_command(json_output: bool) -> None:
    """List packaged synthetic fault scenarios."""

    try:
        scenarios = load_builtin_scenarios()
    except SessionResumeInputError as exc:
        raise SessionResumeUsageError(str(exc)) from exc
    if json_output:
        payload = [
            {
                "scenario_id": item.scenario_id,
                "title": item.title,
                "protocol_version": item.protocol_version.value,
            }
            for item in scenarios.values()
        ]
        click.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    table = Table(title=f"MCP Session Resume Fault Lab ({len(scenarios)} scenarios)")
    table.add_column("Scenario", style="cyan", no_wrap=True)
    table.add_column("Protocol", style="magenta")
    table.add_column("Purpose")
    for item in scenarios.values():
        table.add_row(item.scenario_id, item.protocol_version.value, item.title)
    console.print(table)


@session_resume.command("run")
@click.argument("scenario", required=False)
@click.option("--all", "run_all", is_flag=True, help="Run every packaged fault scenario.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Choose a readable or canonical machine report.",
)
def run_command(scenario: str | None, run_all: bool, output_format: Literal["text", "json"]) -> None:
    """Run one built-in ID or supplied JSON scenario; use --all for the corpus."""

    if run_all and scenario is not None:
        raise SessionResumeUsageError("SCENARIO and --all are mutually exclusive")
    if not run_all and scenario is None:
        raise SessionResumeUsageError("provide a built-in SCENARIO ID, JSON path, or --all")
    try:
        if run_all:
            report: SessionResumeReport | SessionResumeSuiteReport = run_builtin_suite()
        else:
            assert scenario is not None
            path = Path(scenario)
            if path.exists() or path.suffix.lower() == ".json":
                selected = load_scenario_path(path)
            else:
                builtins = load_builtin_scenarios()
                if scenario not in builtins:
                    raise SessionResumeInputError("unknown built-in scenario ID")
                selected = builtins[scenario]
            report = run_scenario(selected)
    except SessionResumeInputError as exc:
        raise SessionResumeUsageError(str(exc)) from exc

    if output_format == "json":
        click.echo(report_json_bytes(report).decode("utf-8"), nl=False)
    elif isinstance(report, SessionResumeSuiteReport):
        _render_suite(report)
    else:
        _render_report(report)


@session_resume.command("schema")
@click.argument("contract", type=click.Choice(["scenario", "transcript", "report", "suite-report"]))
def schema_command(contract: str) -> None:
    """Print an authoritative strict JSON Schema."""

    models: dict[str, type[BaseModel]] = {
        "scenario": SessionResumeScenario,
        "transcript": SessionResumeTranscript,
        "report": SessionResumeReport,
        "suite-report": SessionResumeSuiteReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))


def _render_report(report: SessionResumeReport) -> None:
    console.print(f"[bold]{report.scenario_id}[/bold] — protocol {report.protocol_version.value}")
    console.print(
        f"Verdict: [bold]{report.verdict.upper()}[/bold] | "
        f"at-most-once={report.safety.at_most_once.value} | "
        f"at-least-once={report.safety.at_least_once.value} | "
        f"duplicate-risk={report.safety.duplicate_risk.value} | "
        f"lost-result-risk={report.safety.lost_result_risk.value}"
    )
    table = Table(title=f"Findings ({len(report.findings)})")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Remediation")
    for finding in report.findings:
        table.add_row(
            finding.rule_id,
            finding.severity.value,
            finding.title,
            finding.remediation,
        )
    console.print(table)
    console.print(
        f"Transcript events: {len(report.transcript.entries)} | "
        "Claim ceiling: local modeled observations only; exactly-once unproven."
    )


def _render_suite(report: SessionResumeSuiteReport) -> None:
    table = Table(title="MCP Session Resume Fault Lab — built-in suite")
    table.add_column("Scenario", style="cyan")
    table.add_column("Protocol")
    table.add_column("Verdict")
    table.add_column("Classifications")
    table.add_column("Findings", justify="right")
    for item in report.reports:
        table.add_row(
            item.scenario_id,
            item.protocol_version.value,
            item.verdict,
            ", ".join(value.value for value in item.safety.classifications),
            str(len(item.findings)),
        )
    console.print(table)
    console.print(
        f"Scenarios: {report.scenario_count} | risk={report.risk_count} | "
        f"unknown={report.unknown_count} | exactly-once unproven"
    )
