"""CLI for the deterministic offline MCP Result Parcel Lab."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel, ValidationError

from mcp_audit.result_parcel_models import ParcelAnalysisReport, ParcelScenario, canonical_json_bytes
from mcp_audit.result_parcel_scanner import (
    ParcelInputError,
    analyze_scenario,
    builtin_scenarios,
    generate_synthetic_scenario,
    report_json_bytes,
    scan_scenario_path,
)


class ResultParcelUsageError(click.ClickException):
    exit_code = 2


@click.group("result-parcel")
def result_parcel() -> None:
    """Compare synthetic MCP result delivery modes entirely offline."""


def _human_report(report: ParcelAnalysisReport) -> str:
    lines = [
        f"Scenario: {report.scenario_id or 'unvalidated'}",
        f"Verdict: {report.verdict.upper()}",
    ]
    if report.recommendation is not None:
        lines.extend(
            [
                (
                    f"Recommendation: {report.recommendation.suitability} — "
                    f"{report.recommendation.selected_mode}"
                ),
                "Why:",
                *[f"  - {reason}" for reason in report.recommendation.reasons],
            ]
        )
        if report.recommendation.conditions:
            lines.extend(
                ["Conditions:", *[f"  - {condition}" for condition in report.recommendation.conditions]]
            )
    if report.dimensions is not None:
        lines.append("Tradeoffs:")
        for name, dimension in report.dimensions:
            lines.append(f"  - {name}: {dimension.state} ({'; '.join(dimension.reasons)})")
    if report.findings:
        lines.append("Findings:")
        for finding in report.findings:
            lines.append(
                f"  - [{finding.severity.upper()}] {finding.rule_id} {finding.title}: "
                f"{finding.explanation} Inputs: {', '.join(finding.input_fields)}"
            )
    if report.unknowns:
        lines.extend(["UNKNOWNs:", *[f"  - {unknown}" for unknown in report.unknowns]])
    lines.append(f"Claim: {report.claim}")
    return "\n".join(lines) + "\n"


@result_parcel.command("analyze")
@click.argument("scenario", required=False, type=click.Path(path_type=Path, dir_okay=False))
@click.option("--builtin", "builtin_name", help="Analyze one named built-in scenario.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
def analyze_command(scenario: Path | None, builtin_name: str | None, output_format: str) -> None:
    """Analyze a supplied JSON scenario or one built-in."""

    if (scenario is None) == (builtin_name is None):
        raise ResultParcelUsageError("provide exactly one SCENARIO path or --builtin name")
    try:
        if builtin_name is not None:
            builtins = builtin_scenarios()
            if builtin_name not in builtins:
                available = ", ".join(sorted(builtins))
                raise ResultParcelUsageError(f"unknown built-in {builtin_name!r}; choose: {available}")
            report = analyze_scenario(builtins[builtin_name])
        else:
            assert scenario is not None
            report = scan_scenario_path(scenario)
    except (ParcelInputError, OSError) as exc:
        raise ResultParcelUsageError(str(exc)) from exc
    if output_format == "json":
        click.echo(report_json_bytes(report).decode("utf-8"), nl=False)
    else:
        click.echo(_human_report(report), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@result_parcel.command("builtins")
def builtins_command() -> None:
    """List deterministic built-in scenario names."""

    for name in sorted(builtin_scenarios()):
        click.echo(name)


@result_parcel.command("generate-large")
@click.option("--scenario-id", required=True)
@click.option("--size-bytes", required=True, type=click.IntRange(min=0))
@click.option("--mode", required=True, type=click.Choice(["inline", "resource_link"]))
@click.option(
    "--sensitivity",
    type=click.Choice(["public", "internal", "confidential", "secret", "unknown"]),
    default="internal",
    show_default=True,
)
def generate_large_command(
    scenario_id: str,
    size_bytes: int,
    mode: str,
    sensitivity: str,
) -> None:
    """Emit synthetic large-payload metadata without allocating payload bytes."""

    try:
        scenario = generate_synthetic_scenario(
            scenario_id=scenario_id,
            size_bytes=size_bytes,
            mode=mode,
            sensitivity=sensitivity,
        )
    except (ValueError, ValidationError) as exc:
        raise ResultParcelUsageError("invalid synthetic scenario parameters") from exc
    click.echo(canonical_json_bytes(scenario).decode("utf-8"), nl=False)


@result_parcel.command("schema")
@click.argument("contract", type=click.Choice(["scenario", "report"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""

    models: dict[str, type[BaseModel]] = {
        "scenario": ParcelScenario,
        "report": ParcelAnalysisReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
