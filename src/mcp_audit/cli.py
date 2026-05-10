"""Click CLI entrypoint for mcp-audit."""

from __future__ import annotations

import logging
import platform
import re
import socket
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import anyio
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import discover_all_configs
from mcp_audit.models import (
    AuditReport,
    ClientType,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    DriftFinding,
    DriftStatus,
    ServerAudit,
    ServerConfig,
    TransportType,
)
from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
from mcp_audit.redaction import redact_text
from mcp_audit.report import ReportGenerator
from mcp_audit.scorer import RiskScorer

console = Console()

_CREDENTIAL_HEAVY_THRESHOLD = 3
_REMOTE_URL = re.compile(r"https?://", re.IGNORECASE)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_PACKAGE_RUNNERS = {"npx", "uvx", "docker"}
_DOCKER_SUBCOMMANDS = {"container", "image", "pull", "run"}


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.version_option(package_name="mcp-permission-audit", prog_name="mcp-audit")
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
    _render_config_health_warnings(servers)


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
    "--config-only",
    is_flag=True,
    default=False,
    help="Scan only --config PATH and ignore discovered MCP configs.",
)
@click.option(
    "--override-config",
    "override_config_path",
    default=None,
    metavar="PATH",
    help="Override config YAML (default: ~/.mcp-audit.yaml).",
)
@click.option("--policy", "policy_path", default=None, metavar="PATH", help="Local policy gate YAML.")
@click.option(
    "--inject-check",
    is_flag=True,
    default=False,
    help="Scan for prompt injection in tool, prompt, and resource text.",
)
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
    config_only: bool,
    override_config_path: str | None,
    policy_path: str | None,
    inject_check: bool,
    pin_check: bool,
    llm_analysis: bool,
) -> None:
    """Full audit: discover servers, connect, enumerate tools, score risk, report."""
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")

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
        policy_path,
        inject_check,
        pin_check,
        llm_analysis,
        config_only,
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
    config_only: bool = False,
) -> AuditReport:
    """Core scan pipeline — discovers, connects, analyzes, scores. Returns AuditReport."""
    import os

    start = time.monotonic()

    # 1. Discover servers
    servers = [] if config_only else discover_all_configs(clients)

    if extra_config:
        extra_servers = _parse_extra_config(Path(extra_config))
        servers = extra_servers if config_only else servers + extra_servers

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
                    "Run: pip install 'mcp-permission-audit[llm]'[/yellow]"
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
            audit.capability_findings = analyzer.analyze_capabilities(audit.prompts, audit.resources)
            audit.risk_score = scorer.score_server(audit.permissions)

            # Optional injection detection
            if injection_detector is not None:
                audit.injection_findings = injection_detector.scan_server(
                    audit.tools, audit.prompts, audit.resources
                )

            audit.non_tool_risk = scorer.score_non_tool(audit.capability_findings, audit.injection_findings)

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
        config_health_findings=_config_health_findings(servers),
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
    policy_path: str | None,
    inject_check: bool = False,
    pin_check: bool = False,
    llm_analysis: bool = False,
    config_only: bool = False,
) -> None:
    """CLI scan entrypoint — calls _run_scan_core then renders output."""
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")

    if not config_only and not discover_all_configs(None) and not extra_config:
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
        config_only=config_only,
    )

    if policy_path:
        from mcp_audit.policy import evaluate_policy, load_policy

        try:
            policy = load_policy(Path(policy_path))
        except Exception as exc:
            console.print(f"[red]Failed to load policy {policy_path}: {redact_text(str(exc))}[/red]")
            raise SystemExit(1) from exc
        report.policy_result = evaluate_policy(report, policy)

    if not report.audits:
        console.print("[yellow]No MCP servers found.[/yellow]")
        return

    _render_config_health_warnings([audit.server for audit in report.audits])

    gen = ReportGenerator(console=console)
    gen.render_terminal(report, verbose=verbose)

    if json_output:
        gen.render_json(report, Path(json_output))

    if sarif_output:
        import json as _json

        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(report)
        Path(sarif_output).write_text(_json.dumps(sarif_doc, indent=2))

    if report.policy_result is not None and not report.policy_result.passed:
        raise SystemExit(2)


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
        console.print(f"[red]Failed to parse {path}: {redact_text(str(exc))}[/red]")
        return []


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _duplicate_server_config_counts(servers: list[ServerConfig]) -> dict[str, int]:
    counts = Counter(server.name for server in servers)
    return {name: count for name, count in counts.items() if count > 1}


def _conflicting_scope_server_names(servers: list[ServerConfig]) -> dict[str, list[str]]:
    scopes_by_name: dict[str, set[str]] = {}
    for server in servers:
        scope = "global" if server.project_path is None else f"project:{server.project_path}"
        scopes_by_name.setdefault(server.name, set()).add(scope)
    return {
        name: sorted(scopes)
        for name, scopes in scopes_by_name.items()
        if "global" in scopes and any(scope.startswith("project:") for scope in scopes)
    }


def _conflicting_definition_server_names(servers: list[ServerConfig]) -> dict[str, list[str]]:
    definitions_by_name: dict[str, set[str]] = {}
    for server in servers:
        definitions_by_name.setdefault(server.name, set()).add(_server_definition_summary(server))
    return {
        name: sorted(definitions) for name, definitions in definitions_by_name.items() if len(definitions) > 1
    }


def _render_config_health_warnings(servers: list[ServerConfig]) -> None:
    findings = _config_health_findings(servers)
    if not findings:
        return

    console.print("[yellow]Config health warnings found.[/yellow]")
    for finding in findings:
        console.print(f"[yellow]- {finding.summary}[/yellow]")


def _config_health_findings(servers: list[ServerConfig]) -> list[ConfigHealthFinding]:
    findings: list[ConfigHealthFinding] = []

    for name, count in sorted(_duplicate_server_config_counts(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="duplicate_server_name",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' appears {count} times; pins are keyed by server name, so rename "
                    "duplicate MCP server entries before pinning."
                ),
                details=[f"{count} discovered configs share the same server name."],
                remediation="Rename duplicate MCP server entries before creating or refreshing pins.",
            )
        )

    for name, scopes in sorted(_conflicting_scope_server_names(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="conflicting_scope_server_name",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' is configured in both global and project scopes; "
                    "review which entry should be authoritative before pinning."
                ),
                details=scopes,
                remediation=(
                    "If project-local shadowing is intentional, give the project server a unique reviewed "
                    "name before pinning. Otherwise remove the unintended duplicate so reviews and pins "
                    "refer to one authoritative scope."
                ),
            )
        )

    for name, definitions in sorted(_conflicting_definition_server_names(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="conflicting_server_definition",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' has multiple command or URL definitions across discovered configs; "
                    "review which one should be trusted."
                ),
                details=definitions,
                remediation=(
                    "Align duplicate server definitions or rename entries so each reviewed server name "
                    "maps to one intended command or URL."
                ),
            )
        )

    for server in servers:
        if server.transport == TransportType.STDIO and not server.command:
            findings.append(
                ConfigHealthFinding(
                    finding_type="missing_stdio_command",
                    severity=ConfigHealthSeverity.HIGH,
                    server_name=server.name,
                    summary=f"'{server.name}' uses stdio but has no command; connected scans will fail.",
                    details=["stdio transport requires a configured command."],
                    remediation="Add a command for the server or remove the incomplete config entry.",
                )
            )
        if _missing_local_binary(server):
            findings.append(
                ConfigHealthFinding(
                    finding_type="missing_local_binary",
                    severity=ConfigHealthSeverity.HIGH,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' command path does not exist locally; connected scans will fail."
                    ),
                    details=[f"Configured command: {server.command}"],
                    remediation=(
                        "Install the referenced local binary, correct the command path, or remove the stale "
                        "server entry."
                    ),
                )
            )
        if server.transport == TransportType.SSE:
            findings.append(
                ConfigHealthFinding(
                    finding_type="deprecated_sse_transport",
                    severity=ConfigHealthSeverity.LOW,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' uses deprecated SSE transport; prefer Streamable HTTP if supported."
                    ),
                    details=["SSE is a legacy MCP transport."],
                    remediation="Move the server to Streamable HTTP when the server supports it.",
                )
            )
        if server.transport in (TransportType.HTTP, TransportType.SSE) or server.url:
            findings.append(
                ConfigHealthFinding(
                    finding_type="remote_endpoint",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' declares a remote endpoint; connected scans may contact "
                        "the network."
                    ),
                    details=["HTTP or SSE MCP transports contact the configured URL during scans."],
                    remediation="Review the remote endpoint before running connected scans.",
                )
            )
        if _REMOTE_URL.search(_config_command_line(server)):
            findings.append(
                ConfigHealthFinding(
                    finding_type="remote_url_argument",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' command or args include a remote URL; review the outbound target."
                    ),
                    details=["The configured command line contains an HTTP or HTTPS URL."],
                    remediation="Review the URL and package source before connecting to the server.",
                )
            )
        package_runner_source = _package_runner_source(server)
        if package_runner_source is not None:
            findings.append(
                ConfigHealthFinding(
                    finding_type="package_runner_source_review",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' launches through package runner '{_command_name(server.command)}'; "
                        "review the package or image source before connecting."
                    ),
                    details=[f"Source: {redact_text(package_runner_source)}"],
                    remediation=(
                        "Pin package versions or container digests where possible and review the source "
                        "before running connected scans."
                    ),
                )
            )
        command_name = _command_name(server.command)
        if command_name in _SHELL_WRAPPERS:
            findings.append(
                ConfigHealthFinding(
                    finding_type="shell_wrapper_launch",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' launches through shell wrapper '{command_name}'; "
                        "review args before connecting."
                    ),
                    details=["Shell wrappers can hide compound commands in arguments."],
                    remediation="Review the shell arguments before running connected scans.",
                )
            )
        credential_count = len(server.env_keys) + len(server.headers_keys)
        if credential_count >= _CREDENTIAL_HEAVY_THRESHOLD:
            findings.append(
                ConfigHealthFinding(
                    finding_type="credential_heavy_config",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' references {credential_count} credential key names; "
                        "review their access scope."
                    ),
                    details=["Only credential key names are reported; credential values are not stored."],
                    remediation="Confirm the referenced credentials are scoped to the server's purpose.",
                )
            )

    return findings


def _config_command_line(server: ServerConfig) -> str:
    return " ".join(part for part in [server.command, *server.args] if part)


def _missing_local_binary(server: ServerConfig) -> bool:
    if server.transport != TransportType.STDIO or not server.command:
        return False
    command = server.command.strip()
    if "/" in command or "\\" in command:
        return not Path(command).expanduser().exists()
    return False


def _package_runner_source(server: ServerConfig) -> str | None:
    command_name = _command_name(server.command)
    if command_name not in _PACKAGE_RUNNERS:
        return None
    if command_name == "docker":
        return _docker_image_source(server.args)
    return _first_package_source_arg(server.args)


def _first_package_source_arg(args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            return arg
        if arg in {"--package", "--from", "-p"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _docker_image_source(args: list[str]) -> str | None:
    if not args:
        return None
    index = 0
    if args[0] in _DOCKER_SUBCOMMANDS:
        index = 1
    if len(args) > 1 and args[0] == "container" and args[1] == "run":
        index = 2
    while index < len(args):
        arg = args[index]
        if arg in {"--env", "-e", "--name", "--network", "--platform", "--volume", "-v", "--workdir", "-w"}:
            index += 2
            continue
        if arg.startswith("--") and "=" not in arg:
            index += 1
            continue
        if arg.startswith("-") and "=" not in arg:
            index += 1
            continue
        return arg
    return None


def _server_definition_summary(server: ServerConfig) -> str:
    if server.url:
        return f"{server.transport.value} url={redact_text(server.url)}"
    command = server.command or "missing-command"
    source = _package_runner_source(server)
    if source is not None:
        return f"{server.transport.value} command={_command_name(command)} source={redact_text(source)}"
    return f"{server.transport.value} command={_command_name(command)}"


def _command_name(command: str | None) -> str:
    if not command:
        return ""
    normalized = command.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].lower()


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
    "--stale",
    "stale",
    is_flag=True,
    default=False,
    help="Show pinned servers no longer found in MCP client configs.",
)
@click.option(
    "--refresh",
    "refresh_server",
    default=None,
    metavar="NAME",
    help="Review pin drift for one server before refreshing its baseline.",
)
@click.option(
    "--apply",
    "apply_refresh",
    is_flag=True,
    default=False,
    help="Write a reviewed --refresh baseline.",
)
@click.option(
    "--json",
    "json_status",
    is_flag=True,
    default=False,
    help="Emit pin status or refresh review as JSON.",
)
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
    stale: bool,
    refresh_server: str | None,
    apply_refresh: bool,
    json_status: bool,
    pin_file: str | None,
) -> None:
    """Pin tool schemas for drift detection on subsequent scans."""
    from mcp_audit.pinning import DEFAULT_PIN_PATH, PinStore

    store = PinStore(path=Path(pin_file) if pin_file else DEFAULT_PIN_PATH)

    if json_status and not (status or stale or refresh_server):
        raise click.ClickException("--json can only be used with --status, --stale, or --refresh.")

    selected_actions = sum(
        bool(action)
        for action in (
            server_name,
            clear_server,
            status,
            stale,
            refresh_server,
        )
    )
    if selected_actions > 1:
        raise click.ClickException(
            "--server, --clear, --status, --stale, and --refresh are mutually exclusive."
        )

    if apply_refresh and not refresh_server:
        raise click.ClickException("--apply can only be used with --refresh.")

    if clear_server:
        store.remove_server(clear_server)
        console.print(f"[green]Removed pins for server '{clear_server}'.[/green]")
        return

    if status:
        _render_pin_status(store, json_status)
        return

    if stale:
        _render_pin_stale(store, json_status)
        return

    if refresh_server:
        anyio.run(_run_pin_refresh, refresh_server, store, apply_refresh, json_status)
        return

    # Pin servers
    anyio.run(_run_pin, server_name, store)


async def _run_pin(server_name: str | None, store: object) -> None:
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await _run_scan_core(False, None, 10, None, override_applier)
    duplicate_names = _duplicate_server_names(report.audits)

    matched = False
    skipped_ambiguous: set[str] = set()
    for audit in report.audits:
        if server_name and audit.server.name != server_name:
            continue
        matched = True
        if audit.server.name in duplicate_names:
            if audit.server.name not in skipped_ambiguous:
                console.print(f"[yellow]{_ambiguous_pin_message(audit.server.name)}[/yellow]")
                skipped_ambiguous.add(audit.server.name)
            continue
        if audit.connection_status != "connected":
            console.print(
                f"[yellow]Skipped '{audit.server.name}': connection {audit.connection_status}."
                " Use scan --skip-connect for config-only review; pins require live tool schemas.[/yellow]"
            )
            continue
        store.pin_server(audit.server.name, audit.tools)
        console.print(f"[green]Pinned {len(audit.tools)} tool(s) for '{audit.server.name}'.[/green]")

    if server_name and not matched:
        console.print(f"[yellow]Server '{server_name}' not found.[/yellow]")


async def _run_pin_refresh(
    server_name: str,
    store: object,
    apply_refresh: bool,
    json_status: bool = False,
) -> None:
    """Review drift for one server and optionally refresh its pin baseline."""
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await _run_scan_core(False, None, 10, None, override_applier)

    matching_audits = [audit for audit in report.audits if audit.server.name == server_name]
    if not matching_audits:
        if json_status:
            click.echo(_pin_refresh_json(server_name, 0, [], applied=False, error="server not found"))
            return
        console.print(f"[yellow]Server '{server_name}' not found.[/yellow]")
        return
    if len(matching_audits) > 1:
        error = _ambiguous_pin_message(server_name)
        if json_status:
            click.echo(_pin_refresh_json(server_name, 0, [], applied=False, error=error))
            return
        console.print(f"[yellow]{error}[/yellow]")
        return

    audit = matching_audits[0]
    if audit.connection_status != "connected":
        if json_status:
            click.echo(
                _pin_refresh_json(
                    audit.server.name,
                    len(audit.tools),
                    [],
                    applied=False,
                    error=f"connection {audit.connection_status}",
                )
            )
            return
        console.print(
            f"[yellow]Skipped '{audit.server.name}': connection {audit.connection_status}."
            " Pin refresh requires live tool schemas.[/yellow]"
        )
        return

    findings = store.check_drift(audit.server.name, audit.tools)
    if json_status:
        if apply_refresh:
            store.pin_server(audit.server.name, audit.tools)
        click.echo(_pin_refresh_json(audit.server.name, len(audit.tools), findings, applied=apply_refresh))
        return

    _render_pin_refresh_review(audit.server.name, len(audit.tools), findings)

    if not apply_refresh:
        console.print(
            "[yellow]Review complete; no pins were changed. Rerun with --apply to refresh.[/yellow]"
        )
        return

    store.pin_server(audit.server.name, audit.tools)
    console.print(f"[green]Refreshed {len(audit.tools)} pin(s) for '{audit.server.name}'.[/green]")


def _duplicate_server_names(audits: list[ServerAudit]) -> set[str]:
    return set(_duplicate_server_config_counts([audit.server for audit in audits]))


def _ambiguous_pin_message(server_name: str) -> str:
    return (
        f"Skipped '{server_name}': server name appears in multiple discovered MCP configs. "
        "Pins are keyed by server name, so rename duplicate MCP server entries before pinning."
    )


def _pin_refresh_json(
    server_name: str,
    tool_count: int,
    drift_findings: list[DriftFinding],
    *,
    applied: bool,
    error: str | None = None,
) -> str:
    import json

    counts = {status.value: 0 for status in DriftStatus}
    for finding in drift_findings:
        counts[finding.status.value] += 1
    payload = {
        "server": server_name,
        "current_tool_count": tool_count,
        "applied": applied,
        "error": error,
        "drift_counts": counts,
        "drift": [
            {
                "tool_name": finding.tool_name,
                "status": finding.status.value,
                "summary": finding.summary,
                "details": finding.details,
                "remediation": finding.remediation,
            }
            for finding in drift_findings
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _render_pin_refresh_review(
    server_name: str,
    tool_count: int,
    drift_findings: list[DriftFinding],
) -> None:
    from rich.table import Table

    counts = {status: 0 for status in DriftStatus}
    for finding in drift_findings:
        counts[finding.status] += 1

    console.print(f"[bold]Pin refresh review:[/bold] {server_name} ({tool_count} current tool(s))")
    if not drift_findings:
        console.print("[green]No drift found. Current tools already match the pin baseline.[/green]")
        return

    console.print(
        "[yellow]"
        f"{counts[DriftStatus.NEW]} new, "
        f"{counts[DriftStatus.CHANGED]} changed, "
        f"{counts[DriftStatus.REMOVED]} removed"
        "[/yellow]"
    )

    table = Table(show_header=True)
    table.add_column("Status", style="yellow")
    table.add_column("Tool", style="cyan")
    table.add_column("Review note")

    for finding in drift_findings:
        table.add_row(
            finding.status.value,
            finding.tool_name,
            finding.summary or ", ".join(finding.details) or "Review before refreshing.",
        )

    console.print(table)


def _render_pin_status(store: object, json_status: bool) -> None:
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    statuses = store.status()
    total_tools = sum(status.tool_count for status in statuses)

    if json_status:
        import json

        payload = {
            "pin_file": str(store.path),
            "server_count": len(statuses),
            "total_tools": total_tools,
            "servers": [
                {
                    "name": status.server_name,
                    "tool_count": status.tool_count,
                    "oldest_pinned_at": _datetime_or_none(status.oldest_pinned_at),
                    "newest_pinned_at": _datetime_or_none(status.newest_pinned_at),
                    "age": _pin_age(status.newest_pinned_at),
                }
                for status in statuses
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(f"[bold]Pin baseline:[/bold] {len(statuses)} server(s), {total_tools} tool(s)")
    console.print(f"[dim]Pin file: {store.path}[/dim]")

    if not statuses:
        console.print("[dim]No servers pinned.[/dim]")
        return

    from rich.table import Table

    table = Table(show_header=True)
    table.add_column("Server", style="cyan")
    table.add_column("Tools", justify="right")
    table.add_column("Oldest pin")
    table.add_column("Last pin")
    table.add_column("Age")

    for status in statuses:
        table.add_row(
            status.server_name,
            str(status.tool_count),
            _datetime_or_unknown(status.oldest_pinned_at),
            _datetime_or_unknown(status.newest_pinned_at),
            _pin_age(status.newest_pinned_at),
        )

    console.print(table)


def _render_pin_stale(store: object, json_status: bool) -> None:
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    discovered = discover_all_configs(None)
    discovered_names = {server.name for server in discovered}
    stale = store.stale_baselines(discovered_names)

    if json_status:
        import json

        payload = {
            "pin_file": str(store.path),
            "discovered_server_count": len(discovered_names),
            "pinned_server_count": len(store.status()),
            "stale_server_count": len(stale),
            "stale_servers": [
                {
                    "name": status.server_name,
                    "tool_count": status.tool_count,
                    "oldest_pinned_at": _datetime_or_none(status.oldest_pinned_at),
                    "newest_pinned_at": _datetime_or_none(status.newest_pinned_at),
                    "age": _pin_age(status.newest_pinned_at),
                    "reason": status.reason,
                    "remediation": status.remediation,
                }
                for status in stale
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(f"[bold]Stale pin baselines:[/bold] {len(stale)} server(s) not found in current configs")
    console.print(f"[dim]Pin file: {store.path}[/dim]")

    if not stale:
        console.print("[green]No stale server baselines found.[/green]")
        return

    from rich.table import Table

    table = Table(show_header=True)
    table.add_column("Server", style="cyan")
    table.add_column("Tools", justify="right")
    table.add_column("Last pin")
    table.add_column("Age")
    table.add_column("Suggested action")

    for status in stale:
        table.add_row(
            status.server_name,
            str(status.tool_count),
            _datetime_or_unknown(status.newest_pinned_at),
            _pin_age(status.newest_pinned_at),
            status.remediation,
        )

    console.print(table)
    console.print("[yellow]Review only; no pins were changed.[/yellow]")


def _datetime_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _datetime_or_unknown(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value else "unknown"


def _pin_age(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    now = datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    seconds = max(0, int((now - value).total_seconds()))
    if seconds < 60:
        return "less than 1m"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"
