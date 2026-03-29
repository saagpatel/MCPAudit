"""Click CLI entrypoint for mcp-audit."""

import logging

import click
from rich.console import Console
from rich.table import Table

from mcp_audit.discovery import discover_all_configs
from mcp_audit.models import ClientType

console = Console()


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def main(debug: bool) -> None:
    """MCP Permission Auditor — scan and risk-score locally configured MCP servers."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)


@main.command()
@click.option(
    "--client",
    "client_filter",
    default=None,
    help="Filter by client (claude_code, claude_desktop, cursor, vscode, windsurf).",
)
@click.option("--verbose", is_flag=True, default=False, help="Show args and credential key names.")
def discover(client_filter: str | None, verbose: bool) -> None:
    """Discover all configured MCP servers without connecting to them."""
    clients: list[ClientType] | None = None
    if client_filter:
        try:
            clients = [ClientType(client_filter)]
        except ValueError:
            valid = ", ".join(c.value for c in ClientType)
            console.print(f"[red]Unknown client '{client_filter}'. Valid values: {valid}[/red]")
            raise SystemExit(1)

    servers = discover_all_configs(clients)

    if not servers:
        console.print("[yellow]No MCP servers found.[/yellow]")
        return

    table = Table(title=f"Discovered MCP Servers ({len(servers)} total)", show_lines=True)
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Client", style="magenta")
    table.add_column("Scope", style="dim")
    table.add_column("Transport", style="green")
    table.add_column("Command / URL", overflow="fold", max_width=45)
    table.add_column("Credentials", style="dim")

    for s in servers:
        scope = "global" if s.project_path is None else _truncate(s.project_path, 30)
        command_or_url = s.url or s.command or "—"
        if s.args and not verbose:
            command_or_url = f"{command_or_url} [dim](+{len(s.args)} args)[/dim]"
        elif s.args and verbose:
            args_str = " ".join(s.args)
            command_or_url = f"{command_or_url} {_truncate(args_str, 40)}"

        cred_parts: list[str] = []
        if s.env_keys:
            if verbose:
                cred_parts.append(f"env: {', '.join(s.env_keys)}")
            else:
                cred_parts.append(f"{len(s.env_keys)} env key(s)")
        if s.headers_keys:
            if verbose:
                cred_parts.append(f"headers: {', '.join(s.headers_keys)}")
            else:
                cred_parts.append(f"{len(s.headers_keys)} header key(s)")
        cred_str = "; ".join(cred_parts) if cred_parts else "none"

        table.add_row(
            s.name,
            s.client.value,
            scope,
            s.transport.value,
            command_or_url,
            cred_str,
        )

    console.print(table)


@main.command()
@click.option("--json", "json_output", default=None, metavar="PATH", help="Write JSON report to PATH.")
@click.option("--skip-connect", is_flag=True, default=False, help="Skip server connections, config only.")
@click.option("--clients", default=None, help="Comma-separated list of clients to scan.")
@click.option("--timeout", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--verbose", is_flag=True, default=False, help="Show per-tool permission details.")
@click.option("--config", "extra_config", default=None, metavar="PATH", help="Scan a specific config file.")
def scan(
    json_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
) -> None:
    """Full audit: discover servers, connect, enumerate tools, score risk, report."""
    console.print("[yellow]scan command coming in Phase 1.[/yellow]")


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"
