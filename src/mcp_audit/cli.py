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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.pkgverify import ArtifactCapture, ArtifactVerifier, PackageVerifier

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
    EscalationFinding,
    ProvenanceFinding,
    ServerAudit,
    ServerConfig,
    ShadowingFinding,
    TransportType,
    TrifectaFinding,
)
from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
from mcp_audit.redaction import redact_text
from mcp_audit.report import ReportGenerator, scrub_report_identifiers
from mcp_audit.scorer import RiskScorer

console = Console()

_CREDENTIAL_HEAVY_THRESHOLD = 3
_REMOTE_URL = re.compile(r"https?://", re.IGNORECASE)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_PACKAGE_RUNNERS = {"npx", "uvx", "docker"}
_DOCKER_SUBCOMMANDS = {"container", "image", "pull", "run"}


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
                    "Run: pip install 'mcp-audits[llm]'[/yellow]"
                )

    injection_detector = None
    if inject_check:
        from mcp_audit.injection import InjectionDetector

        injection_detector = InjectionDetector()

    ssrf_detector = None
    ssrf_allow: set[str] = set()
    ssrf_suppressed = 0
    if ssrf_check:
        from mcp_audit.ssrf import SsrfDetector, parse_host_allowlist

        ssrf_detector = SsrfDetector()
        ssrf_allow = parse_host_allowlist(ssrf_allowlist)
    elif ssrf_allowlist:
        console.print("[yellow]--ssrf-allowlist has no effect without --ssrf-check.[/yellow]")

    egress_detector = None
    egress_server_allow: dict[str, set[str]] = {}
    if egress_check:
        from mcp_audit.egress import EgressDetector
        from mcp_audit.ssrf import SsrfDetector, parse_host_allowlist

        egress_detector = EgressDetector(
            parse_host_allowlist(egress_allowlist),
            parse_host_allowlist(multi_tenant_hosts),
        )
        # Per-server allowlists (policy ``servers.<name>.egress_allowlist``) are normalised
        # once here and unioned with the global allowlist per server inside the scan loop.
        egress_server_allow = {
            name: parse_host_allowlist(",".join(hosts))
            for name, hosts in (egress_server_allowlists or {}).items()
            if hosts
        }
        # Egress consumes the SSRF caller-controlled signal; ensure SSRF runs to feed it.
        # When SSRF was not explicitly requested it runs as an internal substrate only — its
        # findings are dropped post-loop (see "SSRF substrate suppression") so they never
        # surface in output or trip the fail_on.ssrf gate unasked.
        if ssrf_detector is None:
            ssrf_detector = SsrfDetector()
            console.print(
                "[dim]--egress-check runs SSRF internally to map outbound destinations; "
                "pass --ssrf-check to also report SSRF findings.[/dim]"
            )
    elif egress_allowlist or multi_tenant_hosts:
        console.print(
            "[yellow]--egress-allowlist/--multi-tenant-hosts have no effect without --egress-check.[/yellow]"
        )

    trifecta_analyzer = None
    if trifecta_check:
        from mcp_audit.trifecta import TrifectaAnalyzer

        trifecta_analyzer = TrifectaAnalyzer()

    shadowing_analyzer = None
    if shadow_check:
        from mcp_audit.shadowing import ShadowingAnalyzer

        shadowing_analyzer = ShadowingAnalyzer()

    escalation_analyzer = None
    if escalation_check:
        from mcp_audit.escalation import EscalationAnalyzer

        escalation_analyzer = EscalationAnalyzer()

    provenance_analyzer = None
    if provenance_check:
        from mcp_audit.provenance import ProvenanceAnalyzer

        provenance_analyzer = ProvenanceAnalyzer()

    integrity_analyzer = None
    if integrity_check:
        from mcp_audit.integrity import IntegrityAnalyzer

        integrity_analyzer = IntegrityAnalyzer()

    # One RegistryClient shared by both verifiers so a package's registry JSON (which
    # carries both the published hash and the artifact download URL) is fetched once per
    # scan when --verify-artifacts and --download-artifacts run together. Fresh per scan,
    # so the per-instance cache never serves stale metadata across scans.
    package_verifier = None
    artifact_verifier = None
    if verify_artifacts or download_artifacts:
        from mcp_audit.pkgverify import ArtifactVerifier, PackageVerifier, RegistryClient

        registry_client = RegistryClient()
        if verify_artifacts:
            package_verifier = PackageVerifier(fetch=registry_client.fetch_hash)
        if download_artifacts:
            artifact_verifier = ArtifactVerifier(fetch=registry_client.fetch_artifact)

    # --escalation/provenance/integrity-check, --verify-artifacts and
    # --download-artifacts all imply a pin comparison, so a pin store is needed even
    # when --pin-check was not passed. Drift output stays gated on pin_check.
    pin_store = None
    if (
        pin_check
        or escalation_check
        or provenance_check
        or integrity_check
        or verify_artifacts
        or download_artifacts
    ):
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

            # Optional SSRF detection (allowlist filtering happens in a post-loop pass)
            if ssrf_detector is not None:
                audit.ssrf_findings = ssrf_detector.scan_server(audit.tools, audit.resources)

            # Optional egress detection (consumes the SSRF findings just computed + resource URIs)
            if egress_detector is not None:
                audit.egress_findings = egress_detector.scan_server(audit, egress_server_allow.get(srv.name))

            audit.non_tool_risk = scorer.score_non_tool(audit.capability_findings, audit.injection_findings)

            # Optional pin drift check (gated on --pin-check, not mere store presence)
            if pin_store is not None and pin_check:
                audit.drift_findings = pin_store.check_drift(srv.name, audit.tools)

            # Optional trifecta per-server detection
            if trifecta_analyzer is not None:
                audit.trifecta_findings = trifecta_analyzer.analyze_server(audit)

            # Optional capability-escalation check vs the pin baseline
            if escalation_analyzer is not None and pin_store is not None:
                baseline = pin_store.baseline_tools(srv.name)
                if baseline:
                    audit.escalation_findings = escalation_analyzer.analyze_server(
                        srv.name, baseline, audit.tools
                    )

            # Optional provenance / launch-config drift check vs the pin baseline
            if provenance_analyzer is not None and pin_store is not None:
                baseline_config = pin_store.baseline_config(srv.name)
                if baseline_config:
                    audit.provenance_findings = provenance_analyzer.analyze_server(srv, baseline_config)

            # Optional launch-artifact integrity (on-disk hash) check vs the pin baseline
            if integrity_analyzer is not None and pin_store is not None:
                baseline_artifacts = pin_store.baseline_artifacts(srv.name)
                if baseline_artifacts:
                    audit.integrity_findings = integrity_analyzer.analyze_server(srv.name, baseline_artifacts)

            # Optional registry package verification (network) vs the pin baseline.
            # Runs in a worker thread so the synchronous registry I/O never blocks
            # the anyio event loop.
            if package_verifier is not None and pin_store is not None:
                baseline_pkgs = pin_store.baseline_package_hashes(srv.name)
                if baseline_pkgs:
                    audit.package_verify_findings = await anyio.to_thread.run_sync(
                        package_verifier.analyze_server, srv.name, srv, baseline_pkgs
                    )

            # Optional byte-level artifact verification (network) vs the pin baseline.
            # Downloads + hashes off the event loop so blocking I/O never stalls anyio.
            if artifact_verifier is not None and pin_store is not None:
                baseline_artifact_pkgs = pin_store.baseline_artifact_hashes(srv.name)
                if baseline_artifact_pkgs:
                    audit.artifact_verify_findings = await anyio.to_thread.run_sync(
                        artifact_verifier.analyze_server, srv.name, srv, baseline_artifact_pkgs
                    )

            audits[idx] = audit
            progress.advance(task_id)

        async with anyio.create_task_group() as tg:
            for i, srv in enumerate(servers):
                tg.start_soon(audit_one, i, srv)

    # Escalation needs a baseline; warn if asked for but nothing is pinned.
    if escalation_check and pin_store is not None and not pin_store.pinned_servers():
        console.print(
            "[yellow]--escalation-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture a baseline to compare against.[/yellow]"
        )

    # Provenance needs a config snapshot in the baseline; warn if nothing is pinned.
    if provenance_check and pin_store is not None and not pin_store.pinned_servers():
        console.print(
            "[yellow]--provenance-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture a launch-config baseline to compare against.[/yellow]"
        )

    # Integrity needs artifact hashes in the baseline; warn if nothing is pinned.
    if integrity_check and pin_store is not None and not pin_store.pinned_servers():
        console.print(
            "[yellow]--integrity-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture launch-artifact hashes to compare against.[/yellow]"
        )

    # Package verification needs registry hashes captured with --verify-artifacts.
    if verify_artifacts and pin_store is not None and not pin_store.pinned_servers():
        console.print(
            "[yellow]--verify-artifacts: no pin baseline found. "
            "Run `mcp-audit pin --verify-artifacts` first to capture registry package hashes.[/yellow]"
        )

    # Byte-level artifact verification needs hashes captured with --download-artifacts.
    if download_artifacts and pin_store is not None and not pin_store.pinned_servers():
        console.print(
            "[yellow]--download-artifacts: no pin baseline found. "
            "Run `mcp-audit pin --download-artifacts` first to capture artifact byte-hashes.[/yellow]"
        )

    # Per-server staleness: a server IS pinned but its baseline predates the
    # provenance/integrity snapshot, so it is silently skipped. Surface it so the
    # user knows the check ran but found nothing to compare for those servers.
    if pin_store is not None and (
        provenance_check or integrity_check or verify_artifacts or download_artifacts
    ):
        pinned = set(pin_store.pinned_servers())
        scanned_pinned = [audit.server.name for audit in audits if audit.server.name in pinned]
        if provenance_check:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_config(n) is None)
            if stale:
                console.print(
                    f"[yellow]--provenance-check: {len(stale)} pinned server(s) predate "
                    f"launch-config snapshots and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin` to enable provenance comparison.[/yellow]"
                )
        if integrity_check:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_artifacts(n) is None)
            if stale:
                console.print(
                    f"[yellow]--integrity-check: {len(stale)} pinned server(s) predate "
                    f"artifact-hash capture and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin` to enable integrity comparison.[/yellow]"
                )
        if verify_artifacts:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_package_hashes(n) is None)
            if stale:
                console.print(
                    f"[yellow]--verify-artifacts: {len(stale)} pinned server(s) lack captured "
                    f"registry hashes and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin --verify-artifacts` to enable verification.[/yellow]"
                )
        if download_artifacts:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_artifact_hashes(n) is None)
            if stale:
                console.print(
                    f"[yellow]--download-artifacts: {len(stale)} pinned server(s) lack captured "
                    f"artifact byte-hashes and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin --download-artifacts` to enable verification.[/yellow]"
                )

    # SSRF substrate suppression — when egress ran SSRF only to map its destinations and
    # --ssrf-check was not requested, egress has already consumed the findings, so drop them
    # here (post-loop, beside the allowlist pass) rather than surface them in output or gating.
    if egress_check and not ssrf_check:
        for audit in audits:
            audit.ssrf_findings = []

    # SSRF allowlist suppression — post-loop pass over all audits (outer scope, so
    # the suppressed counter accumulates cleanly).
    if ssrf_allow:
        from mcp_audit.ssrf import filter_allowlisted_ssrf

        for audit in audits:
            audit.ssrf_findings, dropped = filter_allowlisted_ssrf(audit.ssrf_findings, ssrf_allow)
            ssrf_suppressed += dropped
    if ssrf_suppressed:
        console.print(
            f"[dim]--ssrf-allowlist: suppressed {ssrf_suppressed} SSRF finding(s) "
            "with an allowlisted fixed target host.[/dim]"
        )

    # Fleet-level trifecta pass — runs once after all servers are audited
    fleet_trifecta: list[TrifectaFinding] = []
    if trifecta_analyzer is not None:
        fleet_trifecta = trifecta_analyzer.analyze_fleet(audits)

    # Fleet-level shadowing pass — runs once after all servers are audited
    shadowing: list[ShadowingFinding] = []
    if shadowing_analyzer is not None:
        shadowing = shadowing_analyzer.analyze_fleet(audits)

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
        config_health_findings=_config_health_findings(servers),
        fleet_trifecta_findings=fleet_trifecta,
        shadowing_findings=shadowing,
    )
    return report


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
    """CLI scan entrypoint — calls _run_scan_core then renders output."""
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
            console.print(f"[red]Failed to load policy {policy_path}: {redact_text(str(exc))}[/red]")
            raise SystemExit(1) from exc

    report = await _run_scan_core(
        skip_connect,
        client_list,
        timeout,
        extra_config,
        override_applier,
        inject_check=inject_check,
        ssrf_check=ssrf_check,
        ssrf_allowlist=ssrf_allowlist,
        egress_check=egress_check,
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
        pin_check=pin_check,
        trifecta_check=trifecta_check,
        shadow_check=shadow_check,
        escalation_check=escalation_check,
        provenance_check=provenance_check,
        integrity_check=integrity_check,
        verify_artifacts=verify_artifacts,
        download_artifacts=download_artifacts,
        llm_analysis=llm_analysis,
        config_only=config_only,
    )

    if policy is not None:
        from mcp_audit.policy import evaluate_policy

        report.policy_result = evaluate_policy(report, policy)

    gen = ReportGenerator(console=console)

    if report.audits:
        _render_config_health_warnings([audit.server for audit in report.audits])
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
    from mcp_audit.pinning import DEFAULT_PIN_PATH, PinStore

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
    report = await _run_scan_core(False, None, 10, None, override_applier)
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
        console.print(f"[yellow]Server '{server_name}' not found.[/yellow]")


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
