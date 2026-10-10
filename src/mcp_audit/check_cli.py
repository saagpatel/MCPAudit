"""Safe review entry points; the legacy scan interface remains independent."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import ParamSpec, TypeVar

import anyio
import click
import yaml
from rich.console import Console

from mcp_audit.artifact_paths import validate_artifact_paths
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.report import ReportGenerator
from mcp_audit.review_discovery import review_sources, server_identity
from mcp_audit.terminal_summary import summary_console
from mcp_audit.terminal_text import strip_controls, terminal_safe

P = ParamSpec("P")
T = TypeVar("T")


def _source_options(command: Callable[P, T]) -> Callable[P, T]:
    for option in (
        click.option(
            "--config",
            type=click.Path(path_type=Path),
            help="Review this explicit file only; parsed as Claude-style config.",
        ),
        click.option(
            "--include-discovered", is_flag=True, help="Also read supported client config locations."
        ),
        click.option(
            "--project", type=click.Path(path_type=Path), help="Select project scope (default: cwd)."
        ),
        click.option("--details", is_flag=True, help="Show full findings and source coverage."),
    ):
        command = option(command)
    return command


def _print_sources(out: Console, paths: list[tuple[str, str]]) -> None:
    for path, status in paths:
        out.print(terminal_safe(f"{status}: {path}"))
    out.print("Unsupported source: Codex (no adapter). No recursive search or config includes.")
    out.print("Project and workstation entries are listed separately; no client precedence is inferred.")


@click.command()
@_source_options
@click.option("--connect", is_flag=True, help="Connect only to the explicitly selected server identity.")
@click.option("--server", "server_id", metavar="CLIENT:SCOPE:NAME", help="Exact identity from inspect.")
@click.option("--json", "json_stdout", is_flag=True, help="Emit only AuditReport JSON on stdout.")
@click.option("--output-json", type=click.Path(path_type=Path), help="Write AuditReport JSON to FILE.")
@click.option("--sarif", type=click.Path(path_type=Path), help="Write SARIF to FILE.")
@click.option("--html", type=click.Path(path_type=Path), help="Write offline HTML to FILE.")
@click.option("--show-host", is_flag=True, help="Include the hostname in HTML (hidden by default).")
@click.option("--policy", type=click.Path(path_type=Path), help="Evaluate this explicit local policy.")
@click.option("--color", type=click.Choice(["auto", "always", "never"]), default="auto", show_default=True)
def check(
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    details: bool,
    connect: bool,
    server_id: str | None,
    json_stdout: bool,
    output_json: Path | None,
    sarif: Path | None,
    html: Path | None,
    show_host: bool,
    policy: Path | None,
    color: str,
) -> None:
    """Review configs statically; runtime security is not checked by default."""
    if connect and not server_id:
        raise click.ClickException("--connect requires --server CLIENT:SCOPE:NAME from inspect.")
    if server_id and not connect:
        raise click.ClickException("--server requires --connect; use inspect to review identities.")
    out = summary_console(color=color, stderr=json_stdout)
    try:
        sources = review_sources(config, include_discovered, project)
        inputs = [Path(path) for path, status in sources.paths if status != "absent"]
        if policy is not None:
            inputs.append(policy)
        validate_artifact_paths(
            [("--output-json", output_json), ("--sarif", sarif), ("--html", html)], inputs
        )
        servers = sources.servers
        if connect:
            selected = [server for server in servers if server_identity(server) == server_id]
            if len(selected) != 1 or sources.errors:
                raise ValueError(
                    "Selection must match exactly one server with no config diagnostics. Use inspect."
                )
            servers = selected
            out.print(terminal_safe(f"Connecting to {server_id} from {servers[0].config_path}."))
            out.print(
                "Configured code may execute and access the network. "
                "Auditor read-only intent is not a sandbox."
            )
        policy_config = None
        if policy:
            from mcp_audit.policy import load_policy

            try:
                policy_config = load_policy(policy)
            except (OSError, ValueError, yaml.YAMLError) as exc:
                raise click.ClickException(f"Cannot load policy: {type(exc).__name__}") from None
        operation = partial(
            run_scan,
            ScanOptions(
                skip_connect=not connect,
                connect_project_configs=connect,
                config_only=config is not None and not include_discovered,
            ),
            servers=servers,
            parse_errors=sources.errors,
        )
        report = anyio.run(operation)
        if policy_config is not None:
            from mcp_audit.policy import evaluate_policy

            report.policy_result = evaluate_policy(report, policy_config)
        safe_report = report.redacted()
        payload = json.dumps(safe_report.model_dump(mode="json"), indent=2)
        if not json_stdout:
            ReportGenerator(out).render_terminal(
                report,
                verbose=details,
                details=details,
                explicit_config=config is not None and not include_discovered,
            )
            if details:
                for warning in safe_report.warnings:
                    out.print(terminal_safe(warning.message))
                _print_sources(out, sources.paths)
        if output_json:
            output_json.write_text(payload, encoding="utf-8")
        if sarif:
            from mcp_audit.sarif import SarifGenerator

            sarif.write_text(json.dumps(SarifGenerator().generate(safe_report), indent=2), encoding="utf-8")
        if html:
            from mcp_audit.htmlreport import HtmlReportGenerator

            html.write_text(
                HtmlReportGenerator().generate(safe_report, show_host=show_host), encoding="utf-8"
            )
        for path in (output_json, sarif, html):
            if path is not None:
                out.print(terminal_safe(f"Wrote {path}"))
        if json_stdout:
            click.echo(payload)
        if report.policy_result is not None and not report.policy_result.passed:
            raise click.exceptions.Exit(2)
    except (OSError, ValueError) as exc:
        raise click.ClickException(strip_controls(str(exc))) from None


@click.command()
@_source_options
def inspect(config: Path | None, include_discovered: bool, project: Path | None, details: bool) -> None:
    """List server identities, sources and discovery coverage without connecting."""
    try:
        sources = review_sources(config, include_discovered, project)
    except (OSError, ValueError) as exc:
        raise click.ClickException(strip_controls(str(exc))) from None
    out = Console()
    if not sources.servers:
        out.print("No MCP servers found. Try mcp-audit demo or mcp-audit check --config ./mcp.json.")
    if sources.errors:
        out.print("PARTIAL: config diagnostics or skipped sources reduce coverage.")
    for server in sources.servers:
        out.print(
            terminal_safe(f"{server_identity(server)} | source: {server.source_label} | {server.config_path}")
        )
        if details:
            out.print(
                terminal_safe(
                    f"Transport: {server.transport.value}; credential keys: "
                    f"{', '.join(server.env_keys + server.headers_keys) or 'none'}"
                )
            )
    _print_sources(out, sources.paths)


@click.command()
@click.pass_context
def demo(ctx: click.Context) -> None:
    """Review the bundled examples/sandbox synthetic fixture, config-only."""
    ctx.invoke(check, config=Path(__file__).parent / "fixtures" / "demo-mcp-config.json")
    click.echo("Demo: bundled examples/sandbox synthetic fixture; config-only, no discovery or connections.")
