"""Lightweight Click entrypoint; implementations load only on command selection."""

from __future__ import annotations

import logging
from importlib import import_module
from typing import TYPE_CHECKING

import click

from mcp_audit._command_registry import COMMANDS, LazyGroup
from mcp_audit.terminal_text import TerminalSafeLogFilter

if TYPE_CHECKING:
    from mcp_audit._core_cli import _parse_clients as _parse_clients
    from mcp_audit._core_cli import _run_scan as _run_scan
    from mcp_audit._core_cli import _run_scan_core as _run_scan_core


def __getattr__(name: str) -> object:
    # Retain the frozen private scan entrypoints for downstream callers in 2.x.
    if name in {"_run_scan_core", "_run_scan", "_parse_clients"}:
        return getattr(import_module("mcp_audit._core_cli"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _help_all(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        ctx.meta["help_all"] = True
        click.echo(ctx.get_help())
        ctx.exit()


@click.group(cls=LazyGroup, registry=COMMANDS, invoke_without_command=True, no_args_is_help=False)
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.option(
    "--help-all",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_help_all,
    help="Show all command paths, including compatibility aliases.",
)
@click.option("--details", is_flag=True, help="Show details for the bare static review.")
@click.option("--json", "json_stdout", is_flag=True, help="Emit JSON for the bare static review.")
@click.option("--color", type=click.Choice(["auto", "always", "never"]), default="auto", show_default=True)
@click.version_option(package_name="mcp-audits", prog_name="mcp-audit")
@click.pass_context
def main(ctx: click.Context, debug: bool, details: bool, json_stdout: bool, color: str) -> None:
    """Review MCP configs without execution or connections when no command is given."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.addFilter(TerminalSafeLogFilter())
        from mcp_audit.connector import install_transport_log_filters

        install_transport_log_filters()
    if ctx.invoked_subcommand is None:
        command = main.get_command(ctx, "check")
        assert command is not None
        ctx.invoke(command, details=details, json_stdout=json_stdout, color=color)
    elif details or json_stdout or color != "auto":
        raise click.UsageError(
            "Top-level --details/--json/--color require no command; place options after the command."
        )
