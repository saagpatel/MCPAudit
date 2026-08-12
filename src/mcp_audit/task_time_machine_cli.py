"""Click surface for the offline MCP Task Time Machine."""

from __future__ import annotations

import json
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.task_time_machine import (
    TaskTimeMachineInputError,
    builtin_scenarios,
    result_json_bytes,
    scan_scenario_path,
    simulate_scenario,
)
from mcp_audit.task_time_machine_models import TaskScenario, TaskSimulationResult

BUILTIN_NAMES = tuple(sorted(builtin_scenarios()))


class TaskTimeMachineUsageError(click.ClickException):
    exit_code = 2


@click.group("task-time-machine")
def task_time_machine() -> None:
    """Run deterministic MCP Tasks lifecycle scenarios offline."""


@task_time_machine.command("list")
@click.option("--json", "json_output", is_flag=True, help="Emit the built-in names as JSON.")
def list_command(json_output: bool) -> None:
    """List bundled synthetic scenarios."""

    if json_output:
        click.echo(json.dumps({"builtins": list(BUILTIN_NAMES)}, sort_keys=True))
        return
    for name in BUILTIN_NAMES:
        click.echo(name)


@task_time_machine.command("run")
@click.argument(
    "scenario",
    required=False,
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option("--builtin", type=click.Choice(BUILTIN_NAMES), help="Run one bundled scenario.")
@click.option("--json", "json_output", is_flag=True, help="Emit canonical TaskTimeMachineResultV1 JSON.")
def run_command(scenario: Path | None, builtin: str | None, json_output: bool) -> None:
    """Run exactly one user-supplied or bundled scenario."""

    if (scenario is None) == (builtin is None):
        raise TaskTimeMachineUsageError("provide exactly one SCENARIO path or --builtin NAME")
    try:
        if builtin is not None:
            result = simulate_scenario(builtin_scenarios()[builtin])
        else:
            assert scenario is not None
            result = scan_scenario_path(scenario)
    except TaskTimeMachineInputError as exc:
        raise TaskTimeMachineUsageError(str(exc)) from exc
    if json_output:
        click.echo(result_json_bytes(result).decode("utf-8"), nl=False)
    else:
        click.echo(render_human(result))
    if result.verdict != "pass":
        raise click.exceptions.Exit(1)


@task_time_machine.command("schema")
@click.argument("contract", type=click.Choice(["scenario", "result"]))
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""

    models: dict[str, type[BaseModel]] = {
        "scenario": TaskScenario,
        "result": TaskSimulationResult,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))


def render_human(result: TaskSimulationResult) -> str:
    """Explain the complete deterministic transition trace."""

    lines = [
        f"MCP Task Time Machine: {result.scenario_id or 'invalid-scenario'}",
        f"verdict={result.verdict} protocol={result.protocol_version or 'unknown'} ",
        f"spec={result.spec_profile}@{result.spec_revision[:12]}",
        f"order={result.deterministic_order} seed=none final_clock_ms={result.coverage.final_clock_ms}",
        "",
        "Transitions",
    ]
    if not result.transitions:
        lines.append("- none")
    for transition in result.transitions:
        lines.append(
            f"- t={transition.at_ms} seq={transition.sequence} {transition.event_type}: "
            f"{transition.before_status} -> {transition.after_status} [{transition.disposition}; "
            f"{transition.authority}] {transition.explanation}"
        )
    lines.extend(["", "Findings"])
    if not result.findings:
        lines.append("- none")
    for finding in result.findings:
        sequences = ",".join(str(item) for item in finding.event_sequences) or "scenario"
        lines.append(
            f"- {finding.rule_id} {finding.severity}/{finding.requirement_level} "
            f"at {sequences}: {finding.title}. {finding.evidence}"
        )
    lines.extend(["", "Final state"])
    if result.final_task is None:
        lines.append("- no task materialized")
    else:
        final = result.final_task
        lines.append(
            f"- status={final.status} availability={final.availability} version={final.state_version} "
            f"attempt={final.attempt} cancel_requested={str(final.cancel_requested).lower()}"
        )
    lines.append(f"- claim={result.claim}")
    return "\n".join(lines)
