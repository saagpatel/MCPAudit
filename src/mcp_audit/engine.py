"""The scan engine — the public library core behind every mcp-audit surface.

:func:`run_scan` is the one sanctioned entry point into the scan pipeline
(discover -> connect -> analyze -> score). The CLI (``mcp-audit scan``), the
MCP server tools, and the in-memory :mod:`mcp_audit.api` are all thin
consumers of it; downstream packages should import from here rather than
reaching into :mod:`mcp_audit.cli`.

Output discipline: the engine is silent by default. Progress rendering and
advisory warnings only appear when a caller passes a rich ``Console`` — the
CLI does; library and MCP-server callers must not, so machine-readable
channels (JSON stdout, MCP stdio framing) stay clean.
"""

from __future__ import annotations

import os
import platform
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import anyio
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.confighealth import config_health_findings
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import ConfigParseError, discover_all_configs
from mcp_audit.models import (
    AuditReport,
    ClientType,
    ServerAudit,
    ServerConfig,
    ShadowingFinding,
    TrifectaFinding,
)
from mcp_audit.overrides import OverrideApplier, OverrideConfig
from mcp_audit.redaction import redact_text
from mcp_audit.scorer import RiskScorer


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Configuration for one :func:`run_scan` invocation.

    Defaults mirror ``mcp-audit scan`` with no flags: discover everything,
    connect, run only the always-on permission analysis + risk scoring.
    """

    # Scan shape
    skip_connect: bool = False
    config_only: bool = False
    clients: list[ClientType] | None = None
    timeout: int = 10
    extra_config: str | None = None

    # Optional check families
    inject_check: bool = False
    ssrf_check: bool = False
    egress_check: bool = False
    pin_check: bool = False
    trifecta_check: bool = False
    shadow_check: bool = False
    escalation_check: bool = False
    provenance_check: bool = False
    integrity_check: bool = False
    verify_artifacts: bool = False
    download_artifacts: bool = False
    llm_analysis: bool = False

    # Check tuning
    ssrf_allowlist: str | None = None
    egress_allowlist: str | None = None
    multi_tenant_hosts: str | None = None
    egress_server_allowlists: dict[str, list[str]] | None = None


async def run_scan(
    options: ScanOptions | None = None,
    *,
    servers: list[ServerConfig] | None = None,
    override_applier: OverrideApplier | None = None,
    console: Console | None = None,
) -> AuditReport:
    """Run the scan pipeline and return an :class:`AuditReport`.

    When ``servers`` is provided (a pre-parsed list, e.g. from the in-memory
    ``mcp_audit.api`` entrypoint), discovery is skipped entirely and that list
    is scanned as-is — no filesystem access for config discovery.

    ``override_applier`` defaults to a no-op applier; the CLI and MCP server
    pass one loaded from the user's override file. ``console`` defaults to a
    quiet console — pass a real one to get progress + advisory warnings.
    """
    opts = options if options is not None else ScanOptions()
    applier = override_applier if override_applier is not None else OverrideApplier(OverrideConfig())
    out = console if console is not None else Console(quiet=True)

    start = time.monotonic()

    # 1. Discover servers (unless the caller supplied a pre-parsed list).
    parse_errors: list[ConfigParseError] = []
    if servers is None:
        servers = [] if opts.config_only else discover_all_configs(opts.clients, parse_errors)

        if opts.extra_config:
            extra_servers = _parse_extra_config(Path(opts.extra_config))
            servers = extra_servers if opts.config_only else servers + extra_servers

    connector = ServerConnector(timeout=float(opts.timeout))
    analyzer = PermissionAnalyzer()
    scorer = RiskScorer()

    # Optional Phase 3 components
    llm_analyzer = None
    if opts.llm_analysis:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            out.print("[yellow]--llm-analysis: ANTHROPIC_API_KEY not set, skipping LLM analysis.[/yellow]")
        else:
            try:
                from mcp_audit.llm_analyzer import LLMAnalyzer

                llm_analyzer = LLMAnalyzer(api_key=api_key)
            except ImportError:
                out.print(
                    "[yellow]--llm-analysis: anthropic package not installed. "
                    "Run: pip install 'mcp-audits[llm]'[/yellow]"
                )

    injection_detector = None
    if opts.inject_check:
        from mcp_audit.injection import InjectionDetector

        injection_detector = InjectionDetector()

    ssrf_detector = None
    ssrf_allow: set[str] = set()
    ssrf_suppressed = 0
    if opts.ssrf_check:
        from mcp_audit.ssrf import SsrfDetector, parse_host_allowlist

        ssrf_detector = SsrfDetector()
        ssrf_allow = parse_host_allowlist(opts.ssrf_allowlist)
    elif opts.ssrf_allowlist:
        out.print("[yellow]--ssrf-allowlist has no effect without --ssrf-check.[/yellow]")

    egress_detector = None
    egress_server_allow: dict[str, set[str]] = {}
    if opts.egress_check:
        from mcp_audit.egress import EgressDetector
        from mcp_audit.ssrf import SsrfDetector, parse_host_allowlist

        egress_detector = EgressDetector(
            parse_host_allowlist(opts.egress_allowlist),
            parse_host_allowlist(opts.multi_tenant_hosts),
        )
        # Per-server allowlists (policy ``servers.<name>.egress_allowlist``) are normalised
        # once here and unioned with the global allowlist per server inside the scan loop.
        egress_server_allow = {
            name: parse_host_allowlist(",".join(hosts))
            for name, hosts in (opts.egress_server_allowlists or {}).items()
            if hosts
        }
        # Egress consumes the SSRF caller-controlled signal; ensure SSRF runs to feed it.
        # When SSRF was not explicitly requested it runs as an internal substrate only — its
        # findings are dropped post-loop (see "SSRF substrate suppression") so they never
        # surface in output or trip the fail_on.ssrf gate unasked.
        if ssrf_detector is None:
            ssrf_detector = SsrfDetector()
            out.print(
                "[dim]--egress-check runs SSRF internally to map outbound destinations; "
                "pass --ssrf-check to also report SSRF findings.[/dim]"
            )
    elif opts.egress_allowlist or opts.multi_tenant_hosts:
        out.print(
            "[yellow]--egress-allowlist/--multi-tenant-hosts have no effect without --egress-check.[/yellow]"
        )

    trifecta_analyzer = None
    if opts.trifecta_check:
        from mcp_audit.trifecta import TrifectaAnalyzer

        trifecta_analyzer = TrifectaAnalyzer()

    shadowing_analyzer = None
    if opts.shadow_check:
        from mcp_audit.shadowing import ShadowingAnalyzer

        shadowing_analyzer = ShadowingAnalyzer()

    escalation_analyzer = None
    if opts.escalation_check:
        from mcp_audit.escalation import EscalationAnalyzer

        escalation_analyzer = EscalationAnalyzer()

    provenance_analyzer = None
    if opts.provenance_check:
        from mcp_audit.provenance import ProvenanceAnalyzer

        provenance_analyzer = ProvenanceAnalyzer()

    integrity_analyzer = None
    if opts.integrity_check:
        from mcp_audit.integrity import IntegrityAnalyzer

        integrity_analyzer = IntegrityAnalyzer()

    # One RegistryClient shared by both verifiers so a package's registry JSON (which
    # carries both the published hash and the artifact download URL) is fetched once per
    # scan when --verify-artifacts and --download-artifacts run together. Fresh per scan,
    # so the per-instance cache never serves stale metadata across scans.
    package_verifier = None
    artifact_verifier = None
    if opts.verify_artifacts or opts.download_artifacts:
        from mcp_audit.pkgverify import ArtifactVerifier, PackageVerifier, RegistryClient

        registry_client = RegistryClient()
        if opts.verify_artifacts:
            package_verifier = PackageVerifier(fetch=registry_client.fetch_hash)
        if opts.download_artifacts:
            artifact_verifier = ArtifactVerifier(fetch=registry_client.fetch_artifact)

    # --escalation/provenance/integrity-check, --verify-artifacts and
    # --download-artifacts all imply a pin comparison, so a pin store is needed even
    # when --pin-check was not passed. Drift output stays gated on pin_check.
    pin_store = None
    if (
        opts.pin_check
        or opts.escalation_check
        or opts.provenance_check
        or opts.integrity_check
        or opts.verify_artifacts
        or opts.download_artifacts
    ):
        from mcp_audit.pinning import PinStore

        pin_store = PinStore()

    audits: list[ServerAudit] = [ServerAudit(server=s, connection_status="pending") for s in servers]

    # 2. Connect / analyze / score each server concurrently.
    # disable= when silent: even a quiet Console pays a refresh thread plus
    # ~10 discarded renders/second from rich's Live machinery; disabled
    # Progress keeps add_task/advance as safe no-ops with zero overhead.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=out,
        transient=True,
        disable=console is None,
    ) as progress:
        task_id = progress.add_task(f"Auditing {len(servers)} server(s)...", total=len(servers))

        async def audit_one(idx: int, srv: ServerConfig) -> None:
            if opts.skip_connect:
                audit = connector.skip_connect_audit(srv)
            else:
                audit = await connector.connect(srv)

            # Analyze tool list for new permission findings
            if not opts.skip_connect or not audit.permissions:
                raw_findings = analyzer.analyze_server(audit.tools)
            else:
                raw_findings = list(audit.permissions)

            # Optional LLM augmentation for low-confidence tools
            if llm_analyzer is not None:
                llm_findings = await llm_analyzer.analyze_server(audit.tools, raw_findings)
                raw_findings = raw_findings + llm_findings

            # Apply user overrides between analysis and scoring
            audit.permissions = applier.apply(srv.name, raw_findings)
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
            if pin_store is not None and opts.pin_check:
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
    if opts.escalation_check and pin_store is not None and not pin_store.pinned_servers():
        out.print(
            "[yellow]--escalation-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture a baseline to compare against.[/yellow]"
        )

    # Provenance needs a config snapshot in the baseline; warn if nothing is pinned.
    if opts.provenance_check and pin_store is not None and not pin_store.pinned_servers():
        out.print(
            "[yellow]--provenance-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture a launch-config baseline to compare against.[/yellow]"
        )

    # Integrity needs artifact hashes in the baseline; warn if nothing is pinned.
    if opts.integrity_check and pin_store is not None and not pin_store.pinned_servers():
        out.print(
            "[yellow]--integrity-check: no pin baseline found. "
            "Run `mcp-audit pin` first to capture launch-artifact hashes to compare against.[/yellow]"
        )

    # Package verification needs registry hashes captured with --verify-artifacts.
    if opts.verify_artifacts and pin_store is not None and not pin_store.pinned_servers():
        out.print(
            "[yellow]--verify-artifacts: no pin baseline found. "
            "Run `mcp-audit pin --verify-artifacts` first to capture registry package hashes.[/yellow]"
        )

    # Byte-level artifact verification needs hashes captured with --download-artifacts.
    if opts.download_artifacts and pin_store is not None and not pin_store.pinned_servers():
        out.print(
            "[yellow]--download-artifacts: no pin baseline found. "
            "Run `mcp-audit pin --download-artifacts` first to capture artifact byte-hashes.[/yellow]"
        )

    # Per-server staleness: a server IS pinned but its baseline predates the
    # provenance/integrity snapshot, so it is silently skipped. Surface it so the
    # user knows the check ran but found nothing to compare for those servers.
    if pin_store is not None and (
        opts.provenance_check or opts.integrity_check or opts.verify_artifacts or opts.download_artifacts
    ):
        pinned = set(pin_store.pinned_servers())
        scanned_pinned = [audit.server.name for audit in audits if audit.server.name in pinned]
        if opts.provenance_check:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_config(n) is None)
            if stale:
                out.print(
                    f"[yellow]--provenance-check: {len(stale)} pinned server(s) predate "
                    f"launch-config snapshots and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin` to enable provenance comparison.[/yellow]"
                )
        if opts.integrity_check:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_artifacts(n) is None)
            if stale:
                out.print(
                    f"[yellow]--integrity-check: {len(stale)} pinned server(s) predate "
                    f"artifact-hash capture and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin` to enable integrity comparison.[/yellow]"
                )
        if opts.verify_artifacts:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_package_hashes(n) is None)
            if stale:
                out.print(
                    f"[yellow]--verify-artifacts: {len(stale)} pinned server(s) lack captured "
                    f"registry hashes and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin --verify-artifacts` to enable verification.[/yellow]"
                )
        if opts.download_artifacts:
            stale = sorted(n for n in scanned_pinned if pin_store.baseline_artifact_hashes(n) is None)
            if stale:
                out.print(
                    f"[yellow]--download-artifacts: {len(stale)} pinned server(s) lack captured "
                    f"artifact byte-hashes and were skipped: {', '.join(stale)}. "
                    "Re-pin with `mcp-audit pin --download-artifacts` to enable verification.[/yellow]"
                )

    # SSRF substrate suppression — when egress ran SSRF only to map its destinations and
    # --ssrf-check was not requested, egress has already consumed the findings, so drop them
    # here (post-loop, beside the allowlist pass) rather than surface them in output or gating.
    if opts.egress_check and not opts.ssrf_check:
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
        out.print(
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
        config_health_findings=config_health_findings(servers, parse_errors),
        fleet_trifecta_findings=fleet_trifecta,
        shadowing_findings=shadowing,
    )
    return report


def _parse_extra_config(path: Path) -> list[ServerConfig]:
    """Parse an explicitly named standalone config file.

    Raises ValueError on a missing, unreadable, or unparseable file. Unlike
    fleet discovery (where a broken config is skipped so one bad file cannot
    void a sweep), the caller named this exact path: failing silently would let
    a typo degrade into a clean zero-finding report — the worst failure mode
    for a security scanner feeding a downstream gate. Delegates to
    :func:`mcp_audit.api.parse_config` so file-based and in-memory scans honor
    identical config-format handling and error semantics.
    """
    if not path.exists():
        raise ValueError(f"Config file not found: {path}")
    from mcp_audit.api import parse_config

    try:
        return parse_config(path.read_text(encoding="utf-8"), source=str(path))
    except OSError as exc:
        raise ValueError(f"Failed to read {path}: {redact_text(str(exc))}") from exc
    except ValueError as exc:
        raise ValueError(f"Failed to parse {path}: {redact_text(str(exc))}") from exc
