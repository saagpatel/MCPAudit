"""Click CLI entrypoint for mcp-audit."""

from __future__ import annotations

import logging
import platform
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

import anyio
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import discover_all_configs
from mcp_audit.models import AuditReport, ClientType, ServerAudit, ServerConfig
from mcp_audit.report import ReportGenerator
from mcp_audit.scorer import RiskScorer

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

    from rich.table import Table

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
    anyio.run(_run_scan, json_output, skip_connect, clients, timeout, verbose, extra_config)


async def _run_scan(
    json_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
) -> None:
    start = time.monotonic()

    # 1. Discover servers
    client_list = _parse_clients(clients)
    servers = discover_all_configs(client_list)

    if extra_config:
        extra_servers = _parse_extra_config(Path(extra_config))
        servers = servers + extra_servers

    if not servers:
        console.print("[yellow]No MCP servers found.[/yellow]")
        return

    # 2. Connect / analyze / score each server concurrently
    connector = ServerConnector(timeout=float(timeout))
    analyzer = PermissionAnalyzer()
    scorer = RiskScorer()

    audits: list[ServerAudit] = [
        ServerAudit(server=s, connection_status="pending") for s in servers
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            f"Auditing {len(servers)} server(s)...", total=len(servers)
        )

        async def audit_one(idx: int, srv: ServerConfig) -> None:
            if skip_connect:
                audit = connector.skip_connect_audit(srv)
            else:
                audit = await connector.connect(srv)

            if not skip_connect or not audit.permissions:
                audit.permissions = analyzer.analyze_server(audit.tools)

            audit.risk_score = scorer.score_server(audit.permissions)
            audits[idx] = audit
            progress.advance(task_id)

        async with anyio.create_task_group() as tg:
            for i, srv in enumerate(servers):
                tg.start_soon(audit_one, i, srv)

    # 3. Build top-level report
    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname=socket.gethostname(),
        os_platform=platform.system(),
        servers_discovered=len(servers),
        servers_connected=sum(1 for a in audits if a.connection_status == "connected"),
        servers_failed=sum(1 for a in audits if a.connection_status in ("failed", "timeout")),
        total_tools=sum(len(a.tools) for a in audits),
        high_risk_servers=sum(
            1 for a in audits if a.risk_score is not None and a.risk_score.composite >= 7.0
        ),
        audits=audits,
        scan_duration_seconds=time.monotonic() - start,
    )

    # 4. Render
    gen = ReportGenerator(console=console)
    gen.render_terminal(report, verbose=verbose)

    if json_output:
        gen.render_json(report, Path(json_output))


def _parse_clients(clients_str: str | None) -> list[ClientType] | None:
    if not clients_str:
        return None
    result: list[ClientType] = []
    for part in clients_str.split(","):
        part = part.strip()
        try:
            result.append(ClientType(part))
        except ValueError:
            valid = ", ".join(c.value for c in ClientType)
            console.print(f"[red]Unknown client '{part}'. Valid values: {valid}[/red]")
            raise SystemExit(1)
    return result or None


def _parse_extra_config(path: Path) -> list[ServerConfig]:
    """Attempt to parse a standalone config file using Claude Code discoverer as fallback."""
    if not path.exists():
        console.print(f"[red]Config file not found: {path}[/red]")
        return []
    try:
        from mcp_audit.discovery.claude_code import ClaudeCodeDiscoverer
        return ClaudeCodeDiscoverer().parse(path)
    except Exception as exc:
        console.print(f"[red]Failed to parse {path}: {exc}[/red]")
        return []


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"
