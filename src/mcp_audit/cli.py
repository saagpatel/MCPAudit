"""Click CLI entrypoint for mcp-audit."""

from __future__ import annotations

import logging
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.pkgverify import ArtifactCapture, ArtifactVerifier, PackageVerifier

import anyio
import click
from rich.console import Console

from mcp_audit.confighealth import config_health_findings, duplicate_server_config_counts
from mcp_audit.discovery import ConfigParseError, discover_all_configs
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import (
    AuditReport,
    ClientType,
    ConfigHealthFinding,
    DriftFinding,
    DriftStatus,
    EscalationFinding,
    ProvenanceFinding,
    ServerAudit,
    ServerConfig,
)
from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
from mcp_audit.redaction import redact_text
from mcp_audit.report import ReportGenerator, error_console, scrub_report_identifiers

console = Console()


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.version_option(package_name="mcp-audits", prog_name="mcp-audit")
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
            error_console.print(f"[red]Unknown client '{client_filter}'. Valid values: {valid}[/red]")
            raise SystemExit(1) from None

    parse_errors: list[ConfigParseError] = []
    servers = discover_all_configs(clients, parse_errors)

    if not servers:
        _render_config_health_findings(config_health_findings(servers, parse_errors))
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
    _render_config_health_findings(config_health_findings(servers, parse_errors))


@main.command()
@click.option("--json", "json_output", default=None, metavar="PATH", help="Write JSON report to PATH.")
@click.option(
    "--sarif", "sarif_output", default=None, metavar="PATH", help="Write SARIF 2.1.0 report to PATH."
)  # noqa: E501
@click.option(
    "--html", "html_output", default=None, metavar="PATH", help="Write a self-contained HTML report to PATH."
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
def scan(
    json_output: str | None,
    sarif_output: str | None,
    html_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    config_only: bool,
    override_config_path: str | None,
    policy_path: str | None,
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
) -> None:
    """Full audit: discover servers, connect, enumerate tools, score risk, report."""
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")

    anyio.run(
        _run_scan,
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


async def _run_scan(
    json_output: str | None,
    sarif_output: str | None,
    html_output: str | None,
    skip_connect: bool,
    clients: str | None,
    timeout: int,
    verbose: bool,
    extra_config: str | None,
    override_config_path: str | None,
    policy_path: str | None,
    inject_check: bool = False,
    ssrf_check: bool = False,
    ssrf_allowlist: str | None = None,
    egress_check: bool = False,
    egress_allowlist: str | None = None,
    multi_tenant_hosts: str | None = None,
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
    redact: bool = False,
) -> None:
    """CLI scan entrypoint — calls the engine's run_scan then renders output."""
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")

    cfg_path = Path(override_config_path) if override_config_path else DEFAULT_OVERRIDE_PATH
    override_applier = OverrideApplier(load_override_config(cfg_path))
    client_list = _parse_clients(clients)

    # Load the policy up front so its egress_allowlist / multi_tenant_hosts can configure
    # the egress detector; CLI flags merge with the policy-supplied hosts.
    policy = None
    if policy_path:
        from mcp_audit.policy import load_policy

        try:
            policy = load_policy(Path(policy_path))
        except Exception as exc:
            error_console.print(f"[red]Failed to load policy {policy_path}: {redact_text(str(exc))}[/red]")
            raise SystemExit(1) from exc

    scan_options = ScanOptions(
        skip_connect=skip_connect,
        config_only=config_only,
        clients=client_list,
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
        egress_allowlist=_merge_host_args(egress_allowlist, policy.egress_allowlist if policy else []),
        multi_tenant_hosts=_merge_host_args(multi_tenant_hosts, policy.multi_tenant_hosts if policy else []),
        egress_server_allowlists=(
            {
                name: rule.egress_allowlist
                for name, rule in policy.server_rules.items()
                if rule.egress_allowlist
            }
            if policy
            else None
        ),
    )
    try:
        report = await run_scan(scan_options, override_applier=override_applier, console=console)
    except ValueError as exc:
        # A caller-supplied --config path that is missing or unparseable must be
        # a hard error, not a silently-empty scan that passes downstream gates.
        raise click.ClickException(str(exc)) from exc

    if policy is not None:
        from mcp_audit.policy import evaluate_policy

        report.policy_result = evaluate_policy(report, policy)

    gen = ReportGenerator(console=console)

    # Render config-health warnings from the report itself so parse failures
    # surface even when they left nothing to audit.
    _render_config_health_findings(report.config_health_findings)

    if report.audits:
        gen.render_terminal(report, verbose=verbose)
    else:
        # No servers discovered. Fall through so any requested report files are
        # still written — CI consumers (e.g. SARIF upload) always need an
        # artifact to ingest, even when the scan is empty.
        console.print("[yellow]No MCP servers found.[/yellow]")

    # Field-report mode scrubs host/username identifiers from shared artifacts.
    # Terminal output keeps real values for local readability.
    out_report = scrub_report_identifiers(report) if redact else report

    if json_output:
        gen.render_json(out_report, Path(json_output))

    if sarif_output:
        import json as _json

        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(out_report)
        Path(sarif_output).write_text(_json.dumps(sarif_doc, indent=2))

    if html_output:
        from mcp_audit.htmlreport import HtmlReportGenerator

        Path(html_output).write_text(HtmlReportGenerator().generate(out_report))

    if report.policy_result is not None and not report.policy_result.passed:
        raise SystemExit(2)


def _merge_host_args(cli_value: str | None, policy_hosts: list[str]) -> str | None:
    """Merge a comma-separated CLI host arg with policy-supplied hosts into one arg.

    ``parse_host_allowlist`` normalises and dedups downstream, so a plain comma-join is
    sufficient. Returns None when both sources are empty (no hosts configured).
    """
    parts = [cli_value] if cli_value else []
    parts.extend(policy_hosts)
    return ",".join(parts) if parts else None


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
            error_console.print(f"[red]Unknown client '{part}'. Valid values: {valid}[/red]")
            raise SystemExit(1) from None
    return result or None


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _render_config_health_findings(findings: list[ConfigHealthFinding]) -> None:
    if not findings:
        return

    console.print("[yellow]Config health warnings found.[/yellow]")
    for finding in findings:
        console.print(f"[yellow]- {finding.summary}[/yellow]")


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
@click.option(
    "--clear-stale",
    "clear_stale",
    is_flag=True,
    default=False,
    help="Review and optionally remove all stale server pin baselines.",
)
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
    help="Write a reviewed --refresh baseline or --clear-stale cleanup.",
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
@click.option(
    "--verify-artifacts",
    is_flag=True,
    default=False,
    help="Network: also capture npm/PyPI registry package hashes into the baseline (for scan --verify-artifacts).",  # noqa: E501
)
@click.option(
    "--download-artifacts",
    is_flag=True,
    default=False,
    help="Network: also download artifact bytes and capture their byte-hash into the baseline (for scan --download-artifacts).",  # noqa: E501
)
def pin_command(
    server_name: str | None,
    clear_server: str | None,
    clear_stale: bool,
    status: bool,
    stale: bool,
    refresh_server: str | None,
    apply_refresh: bool,
    json_status: bool,
    pin_file: str | None,
    verify_artifacts: bool,
    download_artifacts: bool,
) -> None:
    """Pin tool schemas for drift detection on subsequent scans."""
    from mcp_audit.pinning import DEFAULT_PIN_PATH, PinFileError, PinStore

    store = PinStore(path=Path(pin_file) if pin_file else DEFAULT_PIN_PATH)

    if json_status and not (status or stale or clear_stale or refresh_server):
        raise click.ClickException(
            "--json can only be used with --status, --stale, --clear-stale, or --refresh."
        )

    selected_actions = sum(
        bool(action)
        for action in (
            server_name,
            clear_server,
            clear_stale,
            status,
            stale,
            refresh_server,
        )
    )
    if selected_actions > 1:
        raise click.ClickException(
            "--server, --clear, --clear-stale, --status, --stale, and --refresh are mutually exclusive."
        )

    if apply_refresh and not (refresh_server or clear_stale):
        raise click.ClickException("--apply can only be used with --refresh or --clear-stale.")

    try:
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

        if clear_stale:
            _render_pin_clear_stale(store, json_status, apply_refresh)
            return

        if refresh_server:
            anyio.run(
                _run_pin_refresh,
                refresh_server,
                store,
                apply_refresh,
                json_status,
                verify_artifacts,
                download_artifacts,
            )
            return

        # Pin servers
        anyio.run(_run_pin, server_name, store, verify_artifacts, download_artifacts)
    except PinFileError as exc:
        # Mutations refuse to write through an unparseable pin file — wiping a
        # repairable baseline is worse than failing loudly.
        error_console.print(f"[red]{exc}. Fix or remove the file, then re-run.[/red]")
        raise SystemExit(1) from exc


async def _run_pin(
    server_name: str | None,
    store: object,
    verify_artifacts: bool = False,
    download_artifacts: bool = False,
) -> None:
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await run_scan(ScanOptions(), override_applier=override_applier, console=console)
    duplicate_names = _duplicate_server_names(report.audits)
    verifier, artifact_verifier = _make_registry_verifiers(verify_artifacts, download_artifacts)

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
        pkg_hashes = await anyio.to_thread.run_sync(verifier.capture, audit.server) if verifier else None
        art_capture = await _capture_artifacts(artifact_verifier, audit.server)
        for warning in art_capture.warnings:
            console.print(f"[yellow]{warning}[/yellow]")
        art_hashes = art_capture.hashes
        store.pin_server(
            audit.server.name,
            audit.tools,
            audit.server,
            pkg_hashes or None,
            art_hashes or None,
        )
        suffix = ""
        if pkg_hashes:
            suffix += f" (+{len(pkg_hashes)} registry hash(es))"
        if art_hashes:
            suffix += f" (+{len(art_hashes)} artifact byte-hash(es))"
        console.print(f"[green]Pinned {len(audit.tools)} tool(s) for '{audit.server.name}'{suffix}.[/green]")

    if server_name and not matched:
        error_console.print(f"[red]Server '{server_name}' not found — nothing was pinned.[/red]")
        raise SystemExit(1)


def _make_registry_verifiers(
    verify_artifacts: bool, download_artifacts: bool
) -> tuple[PackageVerifier | None, ArtifactVerifier | None]:
    """Build the MCP025/MCP026 verifiers sharing one RegistryClient (per-scan cache).

    Sharing the client means a package's registry JSON — which carries both the
    published hash and the artifact download URL — is fetched once when both checks run.
    """
    if not (verify_artifacts or download_artifacts):
        return None, None
    from mcp_audit.pkgverify import ArtifactVerifier, PackageVerifier, RegistryClient

    client = RegistryClient()
    package_verifier = PackageVerifier(fetch=client.fetch_hash) if verify_artifacts else None
    artifact_verifier = ArtifactVerifier(fetch=client.fetch_artifact) if download_artifacts else None
    return package_verifier, artifact_verifier


async def _capture_artifacts(
    verifier: ArtifactVerifier | None, server_config: ServerConfig
) -> ArtifactCapture:
    """Download + hash a server's pinned artifacts off the event loop.

    Returns the full capture (storable ``{ref_key: sha256}`` hashes plus any
    warnings for refused tamper-suspected / unverifiable artifacts). The caller
    decides how to surface warnings — console for humans, the JSON payload for
    ``--json`` — so the structured-output path never loses the signal or corrupts
    its stream with console writes. Empty capture when no verifier.
    """
    from mcp_audit.pkgverify import ArtifactCapture

    if verifier is None:
        return ArtifactCapture()
    return await anyio.to_thread.run_sync(verifier.capture, server_config)


async def _run_pin_refresh(
    server_name: str,
    store: object,
    apply_refresh: bool,
    json_status: bool = False,
    verify_artifacts: bool = False,
    download_artifacts: bool = False,
) -> None:
    """Review drift for one server and optionally refresh its pin baseline."""
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS
    from mcp_audit.pkgverify import ArtifactCapture

    assert isinstance(store, PS)
    verifier, artifact_verifier = _make_registry_verifiers(verify_artifacts, download_artifacts)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await run_scan(ScanOptions(), override_applier=override_applier, console=console)

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
    escalation_findings, provenance_findings = _refresh_security_deltas(store, audit)
    # Capture registry hashes only when we will actually re-pin (network call,
    # offloaded to a thread so it doesn't block the event loop).
    refresh_pkgs = (
        await anyio.to_thread.run_sync(verifier.capture, audit.server)
        if (verifier and apply_refresh)
        else None
    )
    art_capture = (
        await _capture_artifacts(artifact_verifier, audit.server) if apply_refresh else ArtifactCapture()
    )
    refresh_artifacts = art_capture.hashes
    if json_status:
        if apply_refresh:
            store.pin_server(
                audit.server.name,
                audit.tools,
                audit.server,
                refresh_pkgs or None,
                refresh_artifacts or None,
            )
        click.echo(
            _pin_refresh_json(
                audit.server.name,
                len(audit.tools),
                findings,
                escalation_findings,
                provenance_findings,
                applied=apply_refresh,
                artifact_warnings=art_capture.warnings,
            )
        )
        return

    for warning in art_capture.warnings:
        console.print(f"[yellow]{warning}[/yellow]")

    _render_pin_refresh_review(
        audit.server.name, len(audit.tools), findings, escalation_findings, provenance_findings
    )

    if not apply_refresh:
        console.print(
            "[yellow]Review complete; no pins were changed. Rerun with --apply to refresh.[/yellow]"
        )
        return

    store.pin_server(
        audit.server.name,
        audit.tools,
        audit.server,
        refresh_pkgs or None,
        refresh_artifacts or None,
    )
    console.print(f"[green]Refreshed {len(audit.tools)} pin(s) for '{audit.server.name}'.[/green]")


def _refresh_security_deltas(
    store: object,
    audit: ServerAudit,
) -> tuple[list[EscalationFinding], list[ProvenanceFinding]]:
    """Compute capability-escalation and provenance deltas vs the pin baseline.

    Surfaced unconditionally in the refresh preview so security-significant
    changes (a tool that gained a dangerous capability, a swapped launch
    command, a new credential key) are reviewed before --apply blesses the new
    baseline. Returns empty lists when no baseline exists yet.
    """
    from mcp_audit.escalation import EscalationAnalyzer
    from mcp_audit.pinning import PinStore as PS
    from mcp_audit.provenance import ProvenanceAnalyzer

    assert isinstance(store, PS)
    escalation_findings: list[EscalationFinding] = []
    provenance_findings: list[ProvenanceFinding] = []

    baseline_tools = store.baseline_tools(audit.server.name)
    if baseline_tools:
        escalation_findings = EscalationAnalyzer().analyze_server(
            audit.server.name, baseline_tools, audit.tools
        )

    baseline_config = store.baseline_config(audit.server.name)
    if baseline_config:
        provenance_findings = ProvenanceAnalyzer().analyze_server(audit.server, baseline_config)

    return escalation_findings, provenance_findings


def _duplicate_server_names(audits: list[ServerAudit]) -> set[str]:
    return set(duplicate_server_config_counts([audit.server for audit in audits]))


def _ambiguous_pin_message(server_name: str) -> str:
    return (
        f"Skipped '{server_name}': server name appears in multiple discovered MCP configs. "
        "Pins are keyed by server name, so rename duplicate MCP server entries before pinning."
    )


def _pin_refresh_json(
    server_name: str,
    tool_count: int,
    drift_findings: list[DriftFinding],
    escalation_findings: list[EscalationFinding] | None = None,
    provenance_findings: list[ProvenanceFinding] | None = None,
    *,
    applied: bool,
    error: str | None = None,
    artifact_warnings: list[str] | None = None,
) -> str:
    import json

    escalation_findings = escalation_findings or []
    provenance_findings = provenance_findings or []
    artifact_warnings = artifact_warnings or []
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
        "escalation": [
            {
                "rule_id": finding.rule_id,
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "tool_name": finding.tool_name,
                "title": finding.title,
                "description": finding.description,
            }
            for finding in escalation_findings
        ],
        "provenance": [
            {
                "rule_id": finding.rule_id,
                "kind": finding.kind.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "summary": finding.summary,
            }
            for finding in provenance_findings
        ],
        "artifact_warnings": artifact_warnings,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _render_pin_refresh_review(
    server_name: str,
    tool_count: int,
    drift_findings: list[DriftFinding],
    escalation_findings: list[EscalationFinding] | None = None,
    provenance_findings: list[ProvenanceFinding] | None = None,
) -> None:
    from rich.table import Table

    escalation_findings = escalation_findings or []
    provenance_findings = provenance_findings or []
    counts = {status: 0 for status in DriftStatus}
    for finding in drift_findings:
        counts[finding.status] += 1

    console.print(f"[bold]Pin refresh review:[/bold] {server_name} ({tool_count} current tool(s))")
    if not (drift_findings or escalation_findings or provenance_findings):
        console.print("[green]No drift found. Current tools already match the pin baseline.[/green]")
        return

    if drift_findings:
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

    _render_refresh_security_section(
        "Capability escalation",
        [(f.rule_id, f.severity.value, f.tool_name, f.title) for f in escalation_findings],
    )
    _render_refresh_security_section(
        "Launch-config / provenance drift",
        [(f.rule_id, f.severity.value, f.server_name, f.summary) for f in provenance_findings],
    )


def _render_refresh_security_section(
    heading: str,
    rows: list[tuple[str, str, str, str]],
) -> None:
    """Render an escalation/provenance delta table in the refresh preview.

    These are shown unconditionally (no --escalation-check / --provenance-check
    needed) so a rug-pull or launch swap can't slip through a baseline refresh.
    """
    if not rows:
        return
    from rich.table import Table

    console.print(f"[bold red]{heading}[/bold red] — review before refreshing the baseline:")
    table = Table(show_header=True)
    table.add_column("Rule", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Target", style="cyan")
    table.add_column("What changed")
    for rule_id, severity, target, detail in rows:
        table.add_row(rule_id, severity, target, detail)
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


def _render_pin_clear_stale(store: object, json_status: bool, apply_clear: bool) -> None:
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    discovered = discover_all_configs(None)
    discovered_names = {server.name for server in discovered}
    stale = store.stale_baselines(discovered_names)
    removed_names = [status.server_name for status in stale] if apply_clear else []

    if apply_clear:
        for server_name in removed_names:
            store.remove_server(server_name)

    if json_status:
        import json

        payload = {
            "pin_file": str(store.path),
            "discovered_server_count": len(discovered_names),
            "pinned_server_count": len(store.status()) + len(removed_names),
            "stale_server_count": len(stale),
            "applied": apply_clear,
            "removed_server_count": len(removed_names),
            "removed_servers": removed_names,
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

    console.print(f"[bold]Stale pin cleanup review:[/bold] {len(stale)} server(s) not found")
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

    for status in stale:
        table.add_row(
            status.server_name,
            str(status.tool_count),
            _datetime_or_unknown(status.newest_pinned_at),
            _pin_age(status.newest_pinned_at),
        )

    console.print(table)

    if not apply_clear:
        console.print("[yellow]Review complete; no pins were changed. Rerun with --apply to clear.[/yellow]")
        return

    console.print(f"[green]Removed {len(removed_names)} stale server baseline(s).[/green]")


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
