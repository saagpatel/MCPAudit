"""Read-only tool-surface review using the public engine and saved pins."""

from __future__ import annotations

import json
from dataclasses import replace
from functools import partial
from pathlib import Path

import anyio
import click
import yaml

from mcp_audit._cli_policy import apply_cli_policy
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.pinning import PinStore
from mcp_audit.policy import PolicyConfig, load_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.review_discovery import review_sources
from mcp_audit.terminal_summary import summary_console
from mcp_audit.terminal_text import terminal_safe


@click.command()
@click.option(
    "--config", required=True, type=click.Path(path_type=Path), help="Review only this explicit config."
)
@click.option(
    "--pin-file", required=True, type=click.Path(path_type=Path), help="Compare against this saved baseline."
)
@click.option(
    "--trusted-keys",
    type=click.Path(path_type=Path),
    help="Public trust store (default: existing pin trust store).",
)
@click.option(
    "--connect",
    is_flag=True,
    help="Opt in to starting configured programs or contacting configured endpoints.",
)
@click.option("--timeout", default=10, type=click.IntRange(min=1), show_default=True)
@click.option(
    "--policy", type=click.Path(path_type=Path), help="Evaluate this local policy; failure exits 2."
)
@click.option(
    "--pin-min-sequence",
    type=click.IntRange(min=1),
    help="Require a trusted signed manifest at this sequence or newer.",
)
@click.option("--json", "json_stdout", is_flag=True, help="Emit only redacted AuditReport JSON on stdout.")
@click.option("--details", is_flag=True, help="Show full findings, warnings, and coverage.")
def shadow(
    config: Path,
    pin_file: Path,
    trusted_keys: Path | None,
    connect: bool,
    timeout: int,
    policy: Path | None,
    pin_min_sequence: int | None,
    json_stdout: bool,
    details: bool,
) -> None:
    """Inspect tool-surface drift and fleet name collisions without proxying calls.

    Static by default. Pin files, trust history, and configs are never updated.
    No tools are called; --connect lists metadata and is not a sandbox.
    """
    try:
        sources = review_sources(config, False, None, ())
        if sources.errors:
            raise click.ClickException("Config diagnostics prevent shadow review; repair the selected file.")
        policy_config = load_policy(policy) if policy is not None else None
        if pin_min_sequence is not None:
            policy_config = replace(
                policy_config or PolicyConfig(),
                pin_min_sequence=max(pin_min_sequence, (policy_config.pin_min_sequence or 0))
                if policy_config
                else pin_min_sequence,
            )
        pins = PinStore(pin_file, trusted_keys_path=trusted_keys, record_verification=False)
        scan_options = ScanOptions(
            config_only=True,
            skip_connect=not connect,
            connect_project_configs=connect,
            timeout=timeout,
            pin_check=True,
            shadow_check=True,
            pin_file=pin_file,
        )
        report = anyio.run(
            partial(
                run_scan,
                scan_options,
                servers=sources.servers,
                pin_store=pins,
            )
        )
        apply_cli_policy(report, scan_options, policy_config, pin_store=pins)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        # Parser exceptions can contain source snippets. Keep diagnostics value-free.
        raise click.ClickException(f"Cannot complete shadow review ({type(exc).__name__}).") from None

    safe_report = report.redacted()
    if json_stdout:
        click.echo(json.dumps(safe_report.model_dump(mode="json"), indent=2))
    else:
        out = summary_console(color="auto")
        ReportGenerator(out).render_terminal(safe_report, details=details, explicit_config=True)
        for warning in safe_report.warnings:
            out.print(terminal_safe(warning.message))
    if report.policy_result is not None and not report.policy_result.passed:
        raise click.exceptions.Exit(2)
