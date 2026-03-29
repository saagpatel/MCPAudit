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
from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
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
@click.option(
    "--sarif", "sarif_output", default=None, metavar="PATH", help="Write SARIF 2.1.0 report to PATH."
)  # noqa: E501
@click.option("--skip-connect", is_flag=True, default=False, help="Skip server connections, config only.")
@click.option("--clients", default=None, help="Comma-separated list of clients to scan.")
@click.option("--timeout", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--verbose", is_flag=True, default=False, help="Show per-tool permission details.")
@click.option("--config", "extra_config", default=None, metavar="PATH", help="Scan a specific config file.")
@click.option(
    "--override-config",
    "override_config_path",
    default=None,
    metavar="PATH",
    help="Override config YAML (default: ~/.mcp-audit.yaml).",
)
@click.option(
    "--inject-check", is_flag=True, default=False, help="Scan for prompt injection in tool descriptions."
)  # noqa: E501
@click.option(
    "--pin-check", is_flag=True, default=False, help="Check for tool schema drift against stored pins."
)  # noqa: E501
@click.option(
    "--llm-analysis",
    is_flag=True,
    default=False,
    help="Augment analysis with LLM classification (requires ANTHROPIC_API_KEY).",
)
def scan(
    json_output: str | None,
    sarif_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    override_config_path: str | None,
    inject_check: bool,
    pin_check: bool,
    llm_analysis: bool,
) -> None:
    """Full audit: discover servers, connect, enumerate tools, score risk, report."""
    anyio.run(
        _run_scan,
        json_output,
        sarif_output,
        skip_connect,
        clients,
        timeout,
        verbose,
        extra_config,
        override_config_path,
        inject_check,
        pin_check,
        llm_analysis,
    )


async def _run_scan_core(
    skip_connect: bool,
    clients: list[ClientType] | None,
    timeout: int,
    extra_config: str | None,
    override_applier: OverrideApplier,
    inject_check: bool = False,
    pin_check: bool = False,
    llm_analysis: bool = False,
) -> AuditReport:
    """Core scan pipeline — discovers, connects, analyzes, scores. Returns AuditReport."""
    import os

    start = time.monotonic()

    # 1. Discover servers
    servers = discover_all_configs(clients)

    if extra_config:
        extra_servers = _parse_extra_config(Path(extra_config))
        servers = servers + extra_servers

    connector = ServerConnector(timeout=float(timeout))
    analyzer = PermissionAnalyzer()
    scorer = RiskScorer()

    # Optional Phase 3 components
    llm_analyzer = None
    if llm_analysis:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            console.print(  # noqa: E501
                "[yellow]--llm-analysis: ANTHROPIC_API_KEY not set, skipping LLM analysis.[/yellow]"
            )
        else:
            try:
                from mcp_audit.llm_analyzer import LLMAnalyzer

                llm_analyzer = LLMAnalyzer(api_key=api_key)
            except ImportError:
                console.print(
                    "[yellow]--llm-analysis: anthropic package not installed. "
                    "Run: pip install 'mcp-audit[llm]'[/yellow]"
                )

    injection_detector = None
    if inject_check:
        from mcp_audit.injection import InjectionDetector

        injection_detector = InjectionDetector()

    pin_store = None
    if pin_check:
        from mcp_audit.pinning import PinStore

        pin_store = PinStore()

    audits: list[ServerAudit] = [ServerAudit(server=s, connection_status="pending") for s in servers]

    # 2. Connect / analyze / score each server concurrently
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Auditing {len(servers)} server(s)...", total=len(servers))

        async def audit_one(idx: int, srv: ServerConfig) -> None:
            if skip_connect:
                audit = connector.skip_connect_audit(srv)
            else:
                audit = await connector.connect(srv)

            # Analyze tool list for new permission findings
            if not skip_connect or not audit.permissions:
                raw_findings = analyzer.analyze_server(audit.tools)
            else:
                raw_findings = list(audit.permissions)

            # Optional LLM augmentation for low-confidence tools
            if llm_analyzer is not None:
                llm_findings = await llm_analyzer.analyze_server(audit.tools, raw_findings)
                raw_findings = raw_findings + llm_findings

            # Apply user overrides between analysis and scoring
            audit.permissions = override_applier.apply(srv.name, raw_findings)
            audit.risk_score = scorer.score_server(audit.permissions)

            # Optional injection detection
            if injection_detector is not None:
                audit.injection_findings = injection_detector.scan_server(audit.tools)

            # Optional pin drift check
            if pin_store is not None:
                audit.drift_findings = pin_store.check_drift(srv.name, audit.tools)

            audits[idx] = audit
            progress.advance(task_id)

        async with anyio.create_task_group() as tg:
            for i, srv in enumerate(servers):
                tg.start_soon(audit_one, i, srv)

    return AuditReport(
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


async def _run_scan(
    json_output: str | None,
    sarif_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    override_config_path: str | None,
    inject_check: bool = False,
    pin_check: bool = False,
    llm_analysis: bool = False,
) -> None:
    """CLI scan entrypoint — calls _run_scan_core then renders output."""
    if not discover_all_configs(None) and not extra_config:
        # Quick early check without building override applier
        servers = discover_all_configs(_parse_clients(clients))
        if not servers:
            console.print("[yellow]No MCP servers found.[/yellow]")
            return

    cfg_path = Path(override_config_path) if override_config_path else DEFAULT_OVERRIDE_PATH
    override_applier = OverrideApplier(load_override_config(cfg_path))
    client_list = _parse_clients(clients)

    report = await _run_scan_core(
        skip_connect,
        client_list,
        timeout,
        extra_config,
        override_applier,
        inject_check=inject_check,
        pin_check=pin_check,
        llm_analysis=llm_analysis,
    )

    if not report.audits:
        console.print("[yellow]No MCP servers found.[/yellow]")
        return

    gen = ReportGenerator(console=console)
    gen.render_terminal(report, verbose=verbose)

    if json_output:
        gen.render_json(report, Path(json_output))

    if sarif_output:
        import json as _json

        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(report)
        Path(sarif_output).write_text(_json.dumps(sarif_doc, indent=2))


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


# Register watch, monitor, serve, pin subcommands
from mcp_audit.monitor import monitor_command  # noqa: E402
from mcp_audit.server import serve_command  # noqa: E402
from mcp_audit.watcher import watch_command  # noqa: E402

main.add_command(watch_command)
main.add_command(monitor_command)
main.add_command(serve_command)


# ---------------------------------------------------------------------------
# pin subcommand
# ---------------------------------------------------------------------------


@main.command("pin")
@click.option("--server", "server_name", default=None, help="Pin only this server by name.")
@click.option("--clear", "clear_server", default=None, metavar="NAME", help="Remove pins for a server.")
@click.option("--status", is_flag=True, default=False, help="Show pin coverage summary.")
@click.option(
    "--pin-file",
    "pin_file",
    default=None,
    metavar="PATH",
    help="Override default pin file location.",
)
def pin_command(
    server_name: str | None,
    clear_server: str | None,
    status: bool,
    pin_file: str | None,
) -> None:
    """Pin tool schemas for drift detection on subsequent scans."""
    from mcp_audit.pinning import DEFAULT_PIN_PATH, PinStore

    store = PinStore(path=Path(pin_file) if pin_file else DEFAULT_PIN_PATH)

    if clear_server:
        store.remove_server(clear_server)
        console.print(f"[green]Removed pins for server '{clear_server}'.[/green]")
        return

    if status:
        pinned = store.pinned_servers()
        if not pinned:
            console.print("[dim]No servers pinned.[/dim]")
        else:
            for name in pinned:
                count = store.tool_count(name)
                console.print(f"  [cyan]{name}[/cyan]: {count} tool(s) pinned")
        return

    # Pin servers
    anyio.run(_run_pin, server_name, store)


async def _run_pin(server_name: str | None, store: object) -> None:
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await _run_scan_core(True, None, 10, None, override_applier)

    for audit in report.audits:
        if server_name and audit.server.name != server_name:
            continue
        store.pin_server(audit.server.name, audit.tools)
        console.print(f"[green]Pinned {len(audit.tools)} tool(s) for '{audit.server.name}'.[/green]")
