"""Click CLI entrypoint for mcp-audit."""

from __future__ import annotations

import json
import logging
import warnings
from datetime import datetime
from functools import partial
from pathlib import Path

import anyio
import click
from rich.console import Console

from mcp_audit.agent_ui_cli import agent_ui
from mcp_audit.authorization_posture_cli import authorization_posture
from mcp_audit.cache_contract_cli import cache_contract
from mcp_audit.check_cli import check, checkup, demo, inspect
from mcp_audit.confighealth import config_health_findings
from mcp_audit.discovery import ConfigParseError, discover_all_configs
from mcp_audit.enforcement_cli import enforcement_fixture
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import (
    AuditReport,
    ClientType,
    ConfigHealthFinding,
    ServerConfig,
)
from mcp_audit.oauth_transcript_cli import oauth_transcript
from mcp_audit.overrides import OverrideApplier
from mcp_audit.report import error_console
from mcp_audit.result_parcel_cli import result_parcel
from mcp_audit.scan_cli import _parse_clients as _parse_clients
from mcp_audit.scan_cli import _run_scan as _run_scan
from mcp_audit.session_resume_cli import session_resume
from mcp_audit.skillscan_cli import skillscan
from mcp_audit.task_time_machine_cli import task_time_machine
from mcp_audit.taxonomy import config_health_rule_id, finding_url, render_finding_reference
from mcp_audit.terminal_text import TerminalSafeLogFilter, strip_controls, terminal_safe

console = Console()
_MAX_SAFEFORGE_SCHEMA_BYTES = 1_048_576
_MAX_SAFEFORGE_RECEIPT_BYTES = 4_194_304


class ReviewGroup(click.Group):
    """Keep specialist commands reachable while leading help with daily tasks."""

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        groups = {
            "Everyday": ("check", "checkup", "inspect", "demo", "explain"),
            "Integrations": ("serve",),
            "Advanced": tuple(
                name
                for name in self.list_commands(ctx)
                if name not in {"check", "checkup", "inspect", "demo", "explain", "serve"}
            ),
        }
        for heading, names in groups.items():
            with formatter.section(heading):
                formatter.write_dl(
                    [
                        (name, self.commands[name].get_short_help_str())
                        for name in names
                        if name in self.commands
                    ]
                )


def _help_all(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        click.echo(ctx.get_help())
        ctx.exit()


@click.group(cls=ReviewGroup, invoke_without_command=True, no_args_is_help=False)
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.option(
    "--help-all",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_help_all,
    help="Show all command groups.",
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
    if ctx.invoked_subcommand is None:
        ctx.invoke(check, details=details, json_stdout=json_stdout, color=color)
    elif details or json_stdout or color != "auto":
        raise click.UsageError(
            "Top-level --details/--json/--color require no command; place options after the command."
        )


main.add_command(check)
main.add_command(checkup)
main.add_command(inspect)
main.add_command(demo)


@main.command()
@click.argument("rule_id")
def explain(rule_id: str) -> None:
    """Explain a finding offline, without reading configs or contacting servers."""
    try:
        entry = render_finding_reference(rule_id.upper())
    except KeyError:
        raise click.BadParameter(
            f"Unknown finding rule: {strip_controls(rule_id)}", param_hint="rule_id"
        ) from None
    click.echo(entry, nl=False)


main.add_command(enforcement_fixture)
main.add_command(agent_ui)
main.add_command(oauth_transcript)
main.add_command(authorization_posture)
main.add_command(cache_contract)
main.add_command(result_parcel)
main.add_command(session_resume)
main.add_command(skillscan)
main.add_command(task_time_machine)


@main.command("safeforge-preinstall")
@click.option(
    "--producer-schema",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
    help="ForgeReceiptV0 JSON Schema exported by the producer.",
)
@click.option(
    "--receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
    help="ForgeReceiptV0 JSON receipt.",
)
@click.option(
    "--artifact-root",
    type=click.Path(path_type=Path),
    required=True,
    help="Generated artifact directory bound by the receipt.",
)
@click.option("--run-id", required=True, help="Portable SafeForge run identifier.")
@click.option("--created-at", required=True, help="Coordinator timestamp in RFC 3339 form.")
@click.option("--coordinator-revision", required=True, help="MCPAudit source revision.")
@click.option("--coordinator-dirty", is_flag=True, default=False, help="Mark coordinator tree dirty.")
def safeforge_preinstall(
    producer_schema: Path,
    receipt: Path,
    artifact_root: Path,
    run_id: str,
    created_at: str,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> None:
    """Verify a forge handoff and run config-only audit without execution."""
    from mcp_audit.safeforge_coordinator import run_safeforge_preinstall

    try:
        producer_payload = _load_safeforge_json(producer_schema, _MAX_SAFEFORGE_SCHEMA_BYTES)
        receipt_payload = _load_safeforge_json(receipt, _MAX_SAFEFORGE_RECEIPT_BYTES)
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if not isinstance(producer_payload, dict) or not isinstance(receipt_payload, dict):
            raise ValueError("producer schema and receipt must be JSON objects")
        if timestamp.tzinfo is None:
            raise ValueError("--created-at must include a timezone")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        click.echo(
            json.dumps(
                {
                    "accepted": False,
                    "error": {"code": "SF-INPUT-INVALID", "message": str(exc)},
                },
                sort_keys=True,
            )
        )
        raise click.exceptions.Exit(2) from None

    operation = partial(
        run_safeforge_preinstall,
        producer_payload,
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=timestamp,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    result = anyio.run(operation)
    click.echo(result.model_dump_json(exclude_none=True))
    if not result.accepted:
        raise click.exceptions.Exit(1)


@main.command("safeforge-run")
@click.option(
    "--producer-schema",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.option(
    "--receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.option("--artifact-root", type=click.Path(path_type=Path), required=True)
@click.option("--run-id", required=True)
@click.option("--created-at", required=True)
@click.option("--coordinator-revision", required=True)
@click.option("--coordinator-dirty", is_flag=True, default=False)
def safeforge_run(
    producer_schema: Path,
    receipt: Path,
    artifact_root: Path,
    run_id: str,
    created_at: str,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> None:
    """Verify, materialize, execute, audit, grade, and finalize in a disposable sandbox."""
    from mcp_audit.safeforge_runtime import run_safeforge_pipeline

    try:
        producer_payload = _load_safeforge_json(producer_schema, _MAX_SAFEFORGE_SCHEMA_BYTES)
        receipt_payload = _load_safeforge_json(receipt, _MAX_SAFEFORGE_RECEIPT_BYTES)
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if not isinstance(producer_payload, dict) or not isinstance(receipt_payload, dict):
            raise ValueError("producer schema and receipt must be JSON objects")
        if timestamp.tzinfo is None:
            raise ValueError("--created-at must include a timezone")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        click.echo(
            json.dumps(
                {"accepted": False, "error": {"code": "SF-INPUT-INVALID", "message": str(exc)}},
                sort_keys=True,
            )
        )
        raise click.exceptions.Exit(2) from None

    operation = partial(
        run_safeforge_pipeline,
        producer_payload,
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=timestamp,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    result = anyio.run(operation)
    click.echo(result.model_dump_json(exclude_none=True))
    if not result.accepted:
        raise click.exceptions.Exit(1)


def _load_safeforge_json(path: Path, maximum_bytes: int) -> object:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ValueError(f"{path.name} exceeds the {maximum_bytes}-byte input limit")
    return json.loads(path.read_text(encoding="utf-8"))


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
            error_console.print(
                terminal_safe(f"Unknown client '{client_filter}'. Valid values: {valid}"), style="red"
            )
            raise SystemExit(1) from None

    parse_errors: list[ConfigParseError] = []
    servers = discover_all_configs(clients, parse_errors)

    if not servers:
        _render_config_health_findings(config_health_findings(servers, parse_errors))
        console.print(
            "[yellow]No MCP servers found. See config diagnostics above for incomplete coverage.[/yellow]"
            if parse_errors
            else "[yellow]No MCP servers found. Configs are absent or server maps are empty.[/yellow]"
        )
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
        command_or_url = terminal_safe(s.url or s.command or "—")
        if s.args and not verbose:
            command_or_url.append(f" (+{len(s.args)} args)", style="dim")
        elif s.args and verbose:
            args_str = " ".join(s.args)
            command_or_url.append(terminal_safe(f" {_truncate(args_str, 40)}"))

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
            terminal_safe(s.name),
            terminal_safe(s.client.value),
            terminal_safe(scope),
            terminal_safe(s.transport.value),
            command_or_url,
            terminal_safe(cred_str),
        )

    console.print(table)
    _render_config_health_findings(config_health_findings(servers, parse_errors))


@main.command()
@click.option("--json", "json_output", default=None, metavar="PATH", help="Write JSON report to PATH.")
@click.option(
    "--sarif", "sarif_output", default=None, metavar="PATH", help="Write SARIF 2.1.0 report to PATH."
)  # noqa: E501
@click.option(
    "--sarif-profile",
    type=click.Choice(["compatibility", "extended"]),
    default="compatibility",
    help="SARIF rule profile; extended includes configuration-health findings.",
)
@click.option(
    "--html", "html_output", default=None, metavar="PATH", help="Write a self-contained HTML report to PATH."
)  # noqa: E501
@click.option("--skip-connect", is_flag=True, default=False, help="Skip server connections, config only.")
@click.option(
    "--connect-project-configs",
    is_flag=True,
    default=False,
    help="Connect to project-scope configs too; may execute code from the current checkout.",
)
@click.option(
    "--canary-check", is_flag=True, help="Exercise an explicit config in-session for runtime drift."
)
@click.option(
    "--canary-calls",
    default=5,
    type=click.IntRange(1, 100),
    show_default=True,
    help="Maximum benign exercise calls per server with --canary-check.",
)
@click.option(
    "--canary-identities",
    default=None,
    type=click.IntRange(1, 2),
    metavar="N",
    help="Canary client identities (1 or 2); default 2 for stdio, 1 for HTTP/SSE. No extra tool calls.",
)
@click.option(
    "--canary-safe-tool",
    "canary_safe_tools",
    multiple=True,
    metavar="SERVER/TOOL",
    help="Mark an empty-argument tool safe; destructive hints still veto calls.",
)
@click.option("--clients", default=None, help="Comma-separated list of clients to scan.")
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    help="Per-server session budget in seconds (connection and listings; excludes queue wait).",
)
@click.option(
    "--max-concurrency",
    default=32,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum simultaneous server sessions.",
)
@click.option("--verbose", is_flag=True, default=False, help="Show per-tool permission details.")
@click.option("--details", is_flag=True, help="Show the legacy tables and all findings.")
@click.option("--color", type=click.Choice(["auto", "always", "never"]), default="auto", show_default=True)
@click.option(
    "--config",
    "extra_config",
    default=None,
    metavar="PATH",
    help="Scan an explicit file; parsed as Claude-style config.",
)
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
    "--ignore", "ignore_rules", multiple=True, metavar="MCP0xx", help="Ignore a finding rule for this run."
)
@click.option("--ignore-reason", help="Reason for one-run ignores (required for HIGH findings).")
@click.option(
    "--inject-check",
    is_flag=True,
    default=False,
    help="Scan metadata for experimental MEDIUM instruction-shaped text and structural hints.",
)
@click.option(
    "--ssrf-check",
    is_flag=True,
    default=False,
    help="Flag SSRF-prone tools/resources (caller-controlled fetch targets).",
)
@click.option(
    "--ssrf-allowlist",
    default=None,
    metavar="HOSTS",
    help="Comma-separated trusted hosts; suppress SSRF findings whose fixed target host is allowlisted (subdomains included). Never suppresses caller-controlled targets.",  # noqa: E501
)
@click.option(
    "--egress-check",
    is_flag=True,
    default=False,
    help="Audit outbound destinations: flag egress outside the allowlist, unbounded caller-controlled targets, and trusted-but-multi-tenant residuals. Includes SSRF analysis.",  # noqa: E501
)
@click.option(
    "--egress-allowlist",
    default=None,
    metavar="HOSTS",
    help="Comma-separated trusted egress destination hosts (subdomains included). With --egress-check, fixed destinations outside this set are flagged.",  # noqa: E501
)
@click.option(
    "--multi-tenant-hosts",
    default=None,
    metavar="HOSTS",
    help="Comma-separated extra multi-tenant hosts treated as trusted-destination residual risk, beyond the curated default set. Effective with --egress-check.",  # noqa: E501
)
@click.option(
    "--pin-check", is_flag=True, default=False, help="Check for tool schema drift against stored pins."
)  # noqa: E501
@click.option(
    "--trifecta-check",
    is_flag=True,
    default=False,
    help="Detect lethal-trifecta (toxic-flow) attack surface: per-server and fleet-level.",
)
@click.option(
    "--shadow-check",
    is_flag=True,
    default=False,
    help="Detect cross-server tool-name shadowing (exact, normalised, homoglyph collisions).",
)
@click.option(
    "--escalation-check",
    is_flag=True,
    default=False,
    help="Detect capability/description-injection escalation vs the pin baseline (implies pin comparison).",  # noqa: E501
)
@click.option(
    "--provenance-check",
    is_flag=True,
    default=False,
    help="Detect launch-config / provenance drift (command, args, URL, credential keys) vs the pin baseline.",  # noqa: E501
)
@click.option(
    "--integrity-check",
    is_flag=True,
    default=False,
    help="Detect on-disk launch-artifact (binary/script) hash drift vs the pin baseline.",
)
@click.option(
    "--verify-artifacts",
    is_flag=True,
    default=False,
    help="Network: verify npm/PyPI package@version registry hashes vs the pin baseline (opt-in, requires `pin --verify-artifacts`).",  # noqa: E501
)
@click.option(
    "--download-artifacts",
    is_flag=True,
    default=False,
    help="Network: download the npm/PyPI artifact bytes and verify their hash vs the published hash and the pin baseline (opt-in, requires `pin --download-artifacts`).",  # noqa: E501
)
@click.option(
    "--llm-analysis",
    is_flag=True,
    default=False,
    help="Augment analysis with LLM classification (requires ANTHROPIC_API_KEY).",
)
@click.option(
    "--redact",
    is_flag=True,
    default=False,
    help="Field-report mode: scrub hostname and home-path usernames from --json/--sarif/--html output (opt-in).",  # noqa: E501
)
@click.option("--show-host", is_flag=True, help="Include the hostname in HTML (hidden by default).")
@click.option("--card", type=click.Path(path_type=Path), help="Write a local counts-only HTML checkup card.")
@click.option("--names", is_flag=True, help="Opt in to server names on the checkup card only.")
@click.option(
    "--previous", type=click.Path(path_type=Path), help="Compare the card with this local report JSON."
)
def scan(
    json_output: str | None,
    sarif_output: str | None,
    sarif_profile: str,
    html_output: str | None,
    show_host: bool,
    skip_connect: bool,
    connect_project_configs: bool,
    clients: str | None,
    timeout: int,
    max_concurrency: int,
    verbose: bool,
    details: bool,
    color: str,
    extra_config: str | None,
    config_only: bool,
    override_config_path: str | None,
    policy_path: str | None,
    ignore_rules: tuple[str, ...],
    ignore_reason: str | None,
    inject_check: bool,
    ssrf_check: bool,
    ssrf_allowlist: str | None,
    egress_check: bool,
    egress_allowlist: str | None,
    multi_tenant_hosts: str | None,
    pin_check: bool,
    trifecta_check: bool,
    shadow_check: bool,
    escalation_check: bool,
    provenance_check: bool,
    integrity_check: bool,
    verify_artifacts: bool,
    download_artifacts: bool,
    llm_analysis: bool,
    redact: bool,
    canary_check: bool,
    canary_calls: int,
    canary_identities: int | None,
    canary_safe_tools: tuple[str, ...],
    card: Path | None,
    names: bool,
    previous: Path | None,
) -> None:
    """Full audit: discover servers, connect, enumerate tools, score risk, report."""
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")

    anyio.run(
        partial(
            _run_scan,
            canary_identities=canary_identities,
            show_host=show_host,
            details=details,
            color=color,
            ignore_rules=ignore_rules,
            ignore_reason=ignore_reason,
            card=card,
            names=names,
            previous=previous,
        ),
        json_output,
        sarif_output,
        html_output,
        skip_connect,
        clients,
        timeout,
        verbose,
        extra_config,
        override_config_path,
        policy_path,
        inject_check,
        ssrf_check,
        ssrf_allowlist,
        egress_check,
        egress_allowlist,
        multi_tenant_hosts,
        pin_check,
        trifecta_check,
        shadow_check,
        escalation_check,
        provenance_check,
        integrity_check,
        verify_artifacts,
        download_artifacts,
        llm_analysis,
        config_only,
        redact,
        canary_check,
        canary_calls,
        canary_safe_tools,
        sarif_profile,
        max_concurrency,
        connect_project_configs,
    )


async def _run_scan_core(
    skip_connect: bool,
    clients: list[ClientType] | None,
    timeout: int,
    extra_config: str | None,
    override_applier: OverrideApplier,
    inject_check: bool = False,
    ssrf_check: bool = False,
    ssrf_allowlist: str | None = None,
    egress_check: bool = False,
    egress_allowlist: str | None = None,
    multi_tenant_hosts: str | None = None,
    egress_server_allowlists: dict[str, list[str]] | None = None,
    pin_check: bool = False,
    trifecta_check: bool = False,
    shadow_check: bool = False,
    escalation_check: bool = False,
    provenance_check: bool = False,
    integrity_check: bool = False,
    verify_artifacts: bool = False,
    download_artifacts: bool = False,
    llm_analysis: bool = False,
    config_only: bool = False,
    servers: list[ServerConfig] | None = None,
) -> AuditReport:
    """Deprecated compatibility alias for :func:`mcp_audit.engine.run_scan`.

    The scan pipeline moved to :mod:`mcp_audit.engine`; this wrapper keeps the
    old private entry point working for external callers (e.g. shadow-mcp)
    until they migrate. It preserves the historical behavior of printing
    progress + advisory warnings to the CLI console.

    FROZEN SURFACE: never extend this signature. New scan options go on
    :class:`mcp_audit.engine.ScanOptions` only — a flag added here but not
    forwarded in the kwargs block below would be silently ignored.
    """
    warnings.warn(
        "mcp_audit.cli._run_scan_core is deprecated; use mcp_audit.engine.run_scan "
        "with mcp_audit.engine.ScanOptions instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    options = ScanOptions(
        skip_connect=skip_connect,
        config_only=config_only,
        clients=clients,
        timeout=timeout,
        extra_config=extra_config,
        inject_check=inject_check,
        ssrf_check=ssrf_check,
        egress_check=egress_check,
        pin_check=pin_check,
        trifecta_check=trifecta_check,
        shadow_check=shadow_check,
        escalation_check=escalation_check,
        provenance_check=provenance_check,
        integrity_check=integrity_check,
        verify_artifacts=verify_artifacts,
        download_artifacts=download_artifacts,
        llm_analysis=llm_analysis,
        ssrf_allowlist=ssrf_allowlist,
        egress_allowlist=egress_allowlist,
        multi_tenant_hosts=multi_tenant_hosts,
        egress_server_allowlists=egress_server_allowlists,
    )
    return await run_scan(options, servers=servers, override_applier=override_applier, console=console)


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _render_config_health_findings(findings: list[ConfigHealthFinding]) -> None:
    if not findings:
        return

    console.print("[yellow]Config health warnings found.[/yellow]")
    for finding in findings:
        console.print(terminal_safe(f"- {finding.summary}"), style="yellow")
        console.print(terminal_safe(f"  How to fix: {finding.remediation}"))
        if finding.config_paths:
            console.print(terminal_safe("  config_path: " + "; ".join(finding.config_paths)))
        console.print(terminal_safe(f"  see: {finding_url(config_health_rule_id(finding.finding_type))}"))


# Register watch, monitor, serve, and pin subcommands
from mcp_audit.monitor import monitor_command  # noqa: E402
from mcp_audit.pin_cli import pin_command  # noqa: E402
from mcp_audit.server import serve_command  # noqa: E402
from mcp_audit.watcher import watch_command  # noqa: E402

main.add_command(watch_command)
main.add_command(monitor_command)
main.add_command(serve_command)
main.add_command(pin_command)
