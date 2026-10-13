"""Watch subcommand — re-run scan on MCP config file changes."""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
from pathlib import Path

import anyio
import click
from rich.console import Console
from rich.text import Text

from mcp_audit.artifact_paths import validate_artifact_paths
from mcp_audit.discovery import discover_all_configs
from mcp_audit.models import AuditReport, ClientType, ServerAudit
from mcp_audit.report import ReportGenerator
from mcp_audit.report import error_console as _error_console
from mcp_audit.terminal_text import TerminalSafeLogFilter, strip_controls, terminal_safe

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())

_console = Console()


@click.command("watch")
@click.option("--json", "json_output", default=None, metavar="PATH", help="Write JSON on each re-scan.")
@click.option("--sarif", "sarif_output", default=None, metavar="PATH", help="Write SARIF on each re-scan.")
@click.option("--skip-connect", is_flag=True, default=False, help="Skip server connections.")
@click.option(
    "--connect-project-configs",
    is_flag=True,
    default=False,
    help="Connect to project-scope configs too; may execute code from the current checkout.",
)
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
    connect_project_configs: bool = False,
) -> None:
    """Watch MCP config files and re-scan on changes. Requires mcp-audits[watch]."""
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
        connect_project_configs,
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
    connect_project_configs: bool = False,
) -> None:
    try:
        from watchfiles import awatch  # type: ignore[import-not-found, unused-ignore]
    except ImportError:
        _error_console.print("[red]watchfiles not installed. Run: pip install 'mcp-audits[watch]'[/red]")
        raise SystemExit(1) from None

    from mcp_audit.client_filter import _parse_clients
    from mcp_audit.engine import ScanOptions, run_scan
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

    client_list = _parse_clients(clients_str)
    cfg_path = Path(override_config_path) if override_config_path else DEFAULT_OVERRIDE_PATH
    override_applier = OverrideApplier(load_override_config(cfg_path))
    scan_options = ScanOptions(
        pin_check=True,
        skip_connect=skip_connect,
        connect_project_configs=connect_project_configs,
        clients=client_list,
        timeout=timeout,
        extra_config=extra_config,
    )
    gen = ReportGenerator(console=_console)

    extra_path = Path(extra_config) if extra_config else None
    watch_paths = _get_watch_paths(client_list, extra_path)
    from mcp_audit.pinning import DEFAULT_PIN_PATH

    _validate_watch_outputs(json_output, sarif_output, [*watch_paths, cfg_path, DEFAULT_PIN_PATH])
    if not watch_paths:
        _console.print("[yellow]No config files found to watch.[/yellow]")
        return

    _console.print(
        terminal_safe(f"Watching {len(watch_paths)} config file(s) for changes. Ctrl+C to stop."), style="dim"
    )

    # Initial scan
    try:
        report = await run_scan(scan_options, override_applier=override_applier, console=_console)
    except ValueError as exc:
        _error_console.print(terminal_safe(f"{exc}"), style="red")
        raise SystemExit(1) from exc
    gen.render_terminal(report, verbose=verbose)
    _validate_watch_outputs(
        json_output, sarif_output, [*_get_watch_paths(client_list, extra_path), cfg_path, DEFAULT_PIN_PATH]
    )
    _write_outputs(report, json_output, sarif_output)

    prev_report = report
    async for _changes in awatch(*[str(p) for p in watch_paths]):
        _console.rule("[dim]Config changed — re-scanning[/dim]")
        new_report = await run_scan(scan_options, override_applier=override_applier, console=_console)
        _render_diff(prev_report, new_report)
        gen.render_terminal(new_report, verbose=verbose)
        _validate_watch_outputs(
            json_output,
            sarif_output,
            [*_get_watch_paths(client_list, extra_path), cfg_path, DEFAULT_PIN_PATH],
        )
        _write_outputs(new_report, json_output, sarif_output)
        prev_report = new_report


def _get_watch_paths(clients: list[ClientType] | None = None, extra_config: Path | None = None) -> list[Path]:
    """Return deduplicated list of existing MCP config file paths."""
    discovered_paths: list[Path] = []
    servers = discover_all_configs(clients, config_paths=discovered_paths)
    discovered_paths.extend(Path(server.config_path) for server in servers)
    paths: list[Path] = []
    seen: set[str] = set()
    for p in discovered_paths:
        identity = str(p)
        if identity not in seen and p.exists():
            paths.append(p)
            seen.add(identity)
    if extra_config is not None and extra_config.exists() and extra_config not in paths:
        paths.append(extra_config)
    return paths


def _render_diff(prev: AuditReport, curr: AuditReport) -> None:
    """Show added/removed servers and significant risk score changes."""

    def identity(audit: ServerAudit) -> tuple[str, str, str]:
        server = audit.server
        return (server.client.value, server.scope, server.name)

    prev_names = {identity(a): a for a in prev.audits}
    curr_names = {identity(a): a for a in curr.audits}

    added = set(curr_names) - set(prev_names)
    removed = set(prev_names) - set(curr_names)

    for client, scope, name in sorted(added):
        _console.print(
            Text.assemble("  ", (strip_controls(f"+ {client}:{scope}:{name}"), "green"), " (new server)")
        )
    for client, scope, name in sorted(removed):
        _console.print(
            Text.assemble("  ", (strip_controls(f"- {client}:{scope}:{name}"), "red"), " (removed)")
        )

    for identity_key in sorted(set(prev_names) & set(curr_names)):
        client, scope, name = identity_key
        prev_score = prev_names[identity_key].risk_score
        curr_score = curr_names[identity_key].risk_score
        if prev_score and curr_score:
            delta = curr_score.composite - prev_score.composite
            if abs(delta) >= 0.5:
                sign = "+" if delta > 0 else ""
                color = "red" if delta > 0 else "green"
                _console.print(
                    Text.assemble(
                        "  ",
                        (
                            strip_controls(
                                f"{client}:{scope}:{name}: {prev_score.composite:.1f} → "
                                f"{curr_score.composite:.1f} ({sign}{delta:.1f})"
                            ),
                            color,
                        ),
                    )
                )


def _write_outputs(report: AuditReport, json_output: str | None, sarif_output: str | None) -> None:
    """Write JSON and/or SARIF outputs if paths are configured."""
    gen = ReportGenerator(console=_console)
    if json_output:
        gen.render_json(report, Path(json_output))
    if sarif_output:
        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(report)
        _atomic_write_text(Path(sarif_output), json.dumps(sarif_doc, indent=2))


def _validate_watch_outputs(json_output: str | None, sarif_output: str | None, inputs: list[Path]) -> None:
    try:
        validate_artifact_paths(
            [
                ("--json", Path(json_output) if json_output else None),
                ("--sarif", Path(sarif_output) if sarif_output else None),
            ],
            inputs,
        )
    except click.BadParameter as exc:
        _error_console.print(terminal_safe(exc.format_message()), style="red")
        raise SystemExit(2) from None


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.stat().st_mode)):
        path.write_text(text, encoding="utf-8")
        return
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
        if mode is not None:
            os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
