"""Watch subcommand — re-run scan on MCP config file changes."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import anyio
import click
from rich.console import Console

from mcp_audit.discovery import discover_all_configs
from mcp_audit.models import AuditReport
from mcp_audit.report import ReportGenerator

logger = logging.getLogger(__name__)

_console = Console()


@click.command("watch")
@click.option("--json", "json_output", default=None, metavar="PATH", help="Write JSON on each re-scan.")
@click.option("--sarif", "sarif_output", default=None, metavar="PATH", help="Write SARIF on each re-scan.")
@click.option("--skip-connect", is_flag=True, default=False, help="Skip server connections.")
@click.option("--clients", default=None, help="Comma-separated client filter.")
@click.option("--timeout", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--verbose", is_flag=True, default=False, help="Show per-tool permission details.")
@click.option("--config", "extra_config", default=None, metavar="PATH", help="Extra config file.")
@click.option(
    "--override-config",
    "override_config_path",
    default=None,
    metavar="PATH",
    help="Override config YAML (default: ~/.mcp-audit.yaml).",
)
def watch_command(
    json_output: str | None,
    sarif_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    override_config_path: str | None,
) -> None:
    """Watch MCP config files and re-scan on changes. Requires mcp-audit[watch]."""
    anyio.run(
        _watch_loop,
        json_output,
        sarif_output,
        skip_connect,
        clients,
        timeout,
        verbose,
        extra_config,
        override_config_path,
    )


async def _watch_loop(
    json_output: str | None,
    sarif_output: str | None,
    skip_connect: bool,
    clients_str: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    override_config_path: str | None,
) -> None:
    try:
        from watchfiles import awatch  # type: ignore[import-not-found]
    except ImportError:
        _console.print("[red]watchfiles not installed. Run: pip install 'mcp-audit[watch]'[/red]")
        raise SystemExit(1)

    from mcp_audit.cli import _parse_clients, _run_scan_core
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

    client_list = _parse_clients(clients_str)
    cfg_path = Path(override_config_path) if override_config_path else DEFAULT_OVERRIDE_PATH
    override_applier = OverrideApplier(load_override_config(cfg_path))
    gen = ReportGenerator(console=_console)

    watch_paths = _get_watch_paths()
    if not watch_paths:
        _console.print("[yellow]No config files found to watch.[/yellow]")
        return

    _console.print(f"[dim]Watching {len(watch_paths)} config file(s) for changes. Ctrl+C to stop.[/dim]")

    # Initial scan
    report = await _run_scan_core(skip_connect, client_list, timeout, extra_config, override_applier)
    gen.render_terminal(report, verbose=verbose)
    _write_outputs(report, json_output, sarif_output)

    prev_report = report
    async for changes in awatch(*[str(p) for p in watch_paths]):
        _console.rule("[dim]Config changed — re-scanning[/dim]")
        new_report = await _run_scan_core(skip_connect, client_list, timeout, extra_config, override_applier)
        _render_diff(prev_report, new_report)
        gen.render_terminal(new_report, verbose=verbose)
        _write_outputs(new_report, json_output, sarif_output)
        prev_report = new_report


def _get_watch_paths() -> list[Path]:
    """Return deduplicated list of existing MCP config file paths."""
    servers = discover_all_configs(None)
    paths: list[Path] = []
    seen: set[str] = set()
    for s in servers:
        if s.config_path not in seen:
            p = Path(s.config_path)
            if p.exists():
                paths.append(p)
                seen.add(s.config_path)
    return paths


def _render_diff(prev: AuditReport, curr: AuditReport) -> None:
    """Show added/removed servers and significant risk score changes."""
    prev_names = {a.server.name: a for a in prev.audits}
    curr_names = {a.server.name: a for a in curr.audits}

    added = set(curr_names) - set(prev_names)
    removed = set(prev_names) - set(curr_names)

    for name in sorted(added):
        _console.print(f"  [green]+ {name}[/green] (new server)")
    for name in sorted(removed):
        _console.print(f"  [red]- {name}[/red] (removed)")

    for name in sorted(set(prev_names) & set(curr_names)):
        prev_score = prev_names[name].risk_score
        curr_score = curr_names[name].risk_score
        if prev_score and curr_score:
            delta = curr_score.composite - prev_score.composite
            if abs(delta) >= 0.5:
                sign = "+" if delta > 0 else ""
                color = "red" if delta > 0 else "green"
                _console.print(
                    f"  [{color}]{name}: {prev_score.composite:.1f} → "
                    f"{curr_score.composite:.1f} ({sign}{delta:.1f})[/{color}]"
                )


def _write_outputs(report: AuditReport, json_output: str | None, sarif_output: str | None) -> None:
    """Write JSON and/or SARIF outputs if paths are configured."""
    gen = ReportGenerator(console=_console)
    if json_output:
        gen.render_json(report, Path(json_output))
    if sarif_output:
        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(report)
        Path(sarif_output).write_text(json.dumps(sarif_doc, indent=2))
