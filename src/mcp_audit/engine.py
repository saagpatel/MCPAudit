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
import shlex
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING, cast

import anyio
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_audit.agent_text import agent_visible_text, prompt_visible_text
from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.confighealth import config_health_findings
from mcp_audit.connector import ServerConnector, describe_exception
from mcp_audit.coverage import OPTIONAL_CHECKS, build_coverage
from mcp_audit.discovery import ConfigParseError, discover_all_configs
from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ClientType,
    ConnectionMode,
    LLMAnalysisReasonCode,
    LLMAnalysisStatus,
    LLMAnalysisSummary,
    PinIntegrityFinding,
    ScanWarning,
    ServerAudit,
    ServerConfig,
    ShadowingFinding,
    TrifectaFinding,
)
from mcp_audit.overrides import OverrideApplier, OverrideConfig
from mcp_audit.redaction import redact_data, redact_text
from mcp_audit.schema_rules import scan_tool_schema
from mcp_audit.scorer import RiskScorer
from mcp_audit.stdio_transport import DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_SURFACE_BYTES
from mcp_audit.terminal_text import terminal_safe
from mcp_audit.text_limits import MAX_FIELD_BYTES, bounded_text


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Configuration for one :func:`run_scan` invocation.

    Defaults mirror ``mcp-audit scan`` with no flags: discover everything,
    connect to workstation configs, run only the always-on permission analysis + risk scoring.
    """

    # Scan shape
    skip_connect: bool = False
    connect_project_configs: bool = False
    config_only: bool = False
    clients: list[ClientType] | None = None
    timeout: int = 10
    extra_config: str | None = None
    pin_file: Path | None = None

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
    canary_check: bool = False
    canary_calls: int = 5
    canary_identities: int | None = None  # transport default: stdio=2, HTTP/SSE=1
    canary_safe_tools: tuple[str, ...] = ()  # server/tool qualified operator marks

    # Check tuning
    ssrf_allowlist: str | None = None
    egress_allowlist: str | None = None
    multi_tenant_hosts: str | None = None
    egress_server_allowlists: dict[str, list[str]] | None = None
    max_concurrency: int = 32
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    max_surface_bytes: int = DEFAULT_MAX_SURFACE_BYTES
    sdk_stdio_fallback: bool = False


if TYPE_CHECKING:
    from mcp_audit.egress import EgressDetector
    from mcp_audit.escalation import EscalationAnalyzer
    from mcp_audit.injection import InjectionDetector
    from mcp_audit.integrity import IntegrityAnalyzer
    from mcp_audit.llm_analyzer import LLMAnalyzer
    from mcp_audit.pinning import PinStore
    from mcp_audit.pkgverify import ArtifactVerifier, PackageVerifier
    from mcp_audit.provenance import ProvenanceAnalyzer
    from mcp_audit.shadowing import ShadowingAnalyzer
    from mcp_audit.ssrf import SsrfDetector
    from mcp_audit.trifecta import TrifectaAnalyzer


@dataclass(slots=True)
class _ScanContext:
    """Mutable state owned by one invocation; never shared across scans."""

    opts: ScanOptions
    applier: OverrideApplier
    out: Console
    start: float
    servers: list[ServerConfig]
    parse_errors: list[ConfigParseError]
    scan_warnings: list[ScanWarning]
    connector: ServerConnector
    connection_limiter: anyio.CapacityLimiter
    analyzer: PermissionAnalyzer
    scorer: RiskScorer
    llm_analyzer: LLMAnalyzer | None
    llm_unavailable_summary: LLMAnalysisSummary | None
    injection_detector: InjectionDetector | None
    ssrf_detector: SsrfDetector | None
    ssrf_allow: set[str]
    egress_detector: EgressDetector | None
    egress_server_allow: dict[str, set[str]]
    trifecta_analyzer: TrifectaAnalyzer | None
    shadowing_analyzer: ShadowingAnalyzer | None
    escalation_analyzer: EscalationAnalyzer | None
    provenance_analyzer: ProvenanceAnalyzer | None
    integrity_analyzer: IntegrityAnalyzer | None
    package_verifier: PackageVerifier | None
    artifact_verifier: ArtifactVerifier | None
    pin_store: PinStore | None
    audits: list[ServerAudit]
    completed: list[set[str]]
    package_coverage: dict[str, list[CheckCoverage]]

    def warn(
        self, code: str, message: str, *, check: str | None = None, servers: list[str] | None = None
    ) -> None:
        # Preserve arrival order on the console; finalization sorts report data only.
        self.scan_warnings.append(ScanWarning(code=code, message=message, check=check, servers=servers or []))
        self.out.print(terminal_safe(message), style="yellow")


async def run_scan(
    options: ScanOptions | None = None,
    *,
    servers: list[ServerConfig] | None = None,
    parse_errors: list[ConfigParseError] | None = None,
    config_paths: list[Path] | None = None,
    override_applier: OverrideApplier | None = None,
    console: Console | None = None,
) -> AuditReport:
    """Run the scan pipeline and return an :class:`AuditReport`.

    When ``servers`` is provided (a pre-parsed list, e.g. from the in-memory
    ``mcp_audit.api`` entrypoint), discovery is skipped entirely and that list
    is scanned as-is — no filesystem access for config discovery.
    ``parse_errors`` carries diagnostics from pre-parsed configs into findings
    and coverage; the caller's list is not modified.
    ``config_paths`` optionally collects encountered filesystem configs, including
    empty and malformed files, for CLI artifact destination protection.

    ``override_applier`` defaults to a no-op applier; the CLI and MCP server
    pass one loaded from the user's override file. ``console`` defaults to a
    quiet console — pass a real one to get progress + advisory warnings.
    """
    opts = options if options is not None else ScanOptions()
    if opts.max_concurrency < 1:
        raise ValueError("Max concurrency must be at least 1.")
    if opts.canary_check and opts.skip_connect:
        raise ValueError("--canary-check cannot be combined with --skip-connect.")
    if opts.canary_check and not 1 <= opts.canary_calls <= 100:
        raise ValueError("Canary calls must be between 1 and 100.")
    if opts.canary_identities is not None and opts.canary_identities not in (1, 2):
        raise ValueError("Canary identities must be 1 or 2.")
    if opts.canary_check and servers is None and not (opts.config_only and opts.extra_config):
        raise ValueError("--canary-check requires --config PATH --config-only (no workstation discovery).")
    applier = override_applier if override_applier is not None else OverrideApplier(OverrideConfig())
    out = console if console is not None else Console(quiet=True)

    start = time.monotonic()

    # 1. Discover servers (unless the caller supplied a pre-parsed list).
    parse_errors = list(parse_errors) if parse_errors is not None else []
    if servers is None:
        if opts.config_only:
            servers = []
        elif config_paths is None:
            servers = discover_all_configs(opts.clients, parse_errors)
        else:
            servers = discover_all_configs(opts.clients, parse_errors, config_paths)

        if opts.extra_config:
            if config_paths is not None:
                config_paths.append(Path(opts.extra_config))
            extra_servers = _parse_extra_config(Path(opts.extra_config), parse_errors)
            servers = extra_servers if opts.config_only else servers + extra_servers

    context = _prepare_scan(opts, servers, parse_errors, applier, out, start)

    # Discovery -> setup/pins -> ordered per-server stages -> fleet/finalization.
    # Disabled progress avoids refresh threads for silent library consumers.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=out,
        transient=True,
        disable=console is None,
    ) as progress:
        task_id = progress.add_task(f"Auditing {len(servers)} server(s)...", total=len(servers))

        async def audit_one_guarded(idx: int, srv: ServerConfig) -> None:
            # An analyzer crash must not cancel sibling audits or retain partial evidence.
            try:
                await _analyze_server(context, idx, srv)
                progress.advance(task_id)
            except Exception as exc:
                context.audits[idx] = ServerAudit(
                    server=srv,
                    connection_status="failed",
                    connection_error=redact_text(f"analysis error: {describe_exception(exc)}"),
                )
                progress.advance(task_id)

        async with anyio.create_task_group() as tg:
            for i, srv in enumerate(servers):
                tg.start_soon(audit_one_guarded, i, srv)

    return _finalize_scan(context)


def _prepare_scan(
    opts: ScanOptions,
    servers: list[ServerConfig],
    parse_errors: list[ConfigParseError],
    applier: OverrideApplier,
    out: Console,
    start: float,
) -> _ScanContext:
    """Initialize optional components and baselines once, before any server task."""
    scan_warnings: list[ScanWarning] = []

    def warn(code: str, message: str, *, check: str | None = None, servers: list[str] | None = None) -> None:
        scan_warnings.append(ScanWarning(code=code, message=message, check=check, servers=servers or []))
        out.print(terminal_safe(message), style="yellow")

    connector = ServerConnector(
        timeout=float(opts.timeout),
        max_frame_bytes=opts.max_frame_bytes,
        max_surface_bytes=opts.max_surface_bytes,
        sdk_stdio_fallback=opts.sdk_stdio_fallback,
    )
    connector.scan_warnings = []
    connection_limiter = anyio.CapacityLimiter(opts.max_concurrency)
    analyzer = PermissionAnalyzer()
    scorer = RiskScorer()

    # Optional Phase 3 components
    llm_analyzer = None
    llm_unavailable_summary: LLMAnalysisSummary | None = None
    if opts.llm_analysis:
        from mcp_audit.llm_analyzer import DEFAULT_MODEL

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            llm_unavailable_summary = LLMAnalysisSummary(
                status=LLMAnalysisStatus.UNKNOWN,
                reason_code=LLMAnalysisReasonCode.MISSING_CREDENTIAL,
                model=DEFAULT_MODEL,
            )
            warn(
                "missing_credential",
                "--llm-analysis: ANTHROPIC_API_KEY not set, skipping LLM analysis.",
                check="llm_analysis",
            )
        else:
            try:
                from mcp_audit.llm_analyzer import LLMAnalyzer

                llm_analyzer = LLMAnalyzer(api_key=api_key)
            except ImportError:
                llm_unavailable_summary = LLMAnalysisSummary(
                    status=LLMAnalysisStatus.UNKNOWN,
                    reason_code=LLMAnalysisReasonCode.MISSING_DEPENDENCY,
                    model=DEFAULT_MODEL,
                )
                warn(
                    "missing_dependency",
                    "--llm-analysis: anthropic package not installed. Run: pip install 'mcp-audits[llm]'",
                    check="llm_analysis",
                )

    injection_detector = None
    if opts.inject_check:
        from mcp_audit.injection import InjectionDetector

        injection_detector = InjectionDetector()

    ssrf_detector = None
    ssrf_allow: set[str] = set()
    if opts.ssrf_check:
        from mcp_audit.ssrf import SsrfDetector, parse_host_allowlist

        ssrf_detector = SsrfDetector()
        ssrf_allow = parse_host_allowlist(opts.ssrf_allowlist)
    elif opts.ssrf_allowlist:
        warn(
            "option_ignored",
            "--ssrf-allowlist has no effect without --ssrf-check.",
            check="ssrf_check",
        )

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
        warn(
            "option_ignored",
            "--egress-allowlist/--multi-tenant-hosts have no effect without --egress-check.",
            check="egress_check",
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

    # Canary first listings and other baseline checks need pins even without
    # --pin-check. Ordinary saved-pin drift output stays gated on pin_check.
    pin_store = None
    if (
        opts.canary_check
        or opts.pin_check
        or opts.escalation_check
        or opts.provenance_check
        or opts.integrity_check
        or opts.verify_artifacts
        or opts.download_artifacts
    ):
        from mcp_audit.pinning import PinStore

        pin_store = PinStore(path=opts.pin_file) if opts.pin_file is not None else PinStore()
        for server in servers:
            scan_warnings.extend(pin_store.schema_warnings(server.name))
        if opts.canary_check and pin_store.read_error:
            warn(
                "pin_baseline_corrupted",
                f"--canary-check: pin baseline could not be parsed ({pin_store.read_error}); "
                "using an in-session baseline only.",
                check="canary_check",
            )

    audits: list[ServerAudit] = [ServerAudit(server=s, connection_status="pending") for s in servers]
    completed: list[set[str]] = [set() for _ in servers]
    package_coverage = {
        check: [CheckCoverage(state="not_run", reason="verification execution unavailable") for _ in servers]
        for check in ("verify_artifacts", "download_artifacts")
        if getattr(opts, check)
    }

    return _ScanContext(
        opts=opts,
        applier=applier,
        out=out,
        start=start,
        servers=servers,
        parse_errors=parse_errors,
        scan_warnings=scan_warnings,
        connector=connector,
        connection_limiter=connection_limiter,
        analyzer=analyzer,
        scorer=scorer,
        llm_analyzer=llm_analyzer,
        llm_unavailable_summary=llm_unavailable_summary,
        injection_detector=injection_detector,
        ssrf_detector=ssrf_detector,
        ssrf_allow=ssrf_allow,
        egress_detector=egress_detector,
        egress_server_allow=egress_server_allow,
        trifecta_analyzer=trifecta_analyzer,
        shadowing_analyzer=shadowing_analyzer,
        escalation_analyzer=escalation_analyzer,
        provenance_analyzer=provenance_analyzer,
        integrity_analyzer=integrity_analyzer,
        package_verifier=package_verifier,
        artifact_verifier=artifact_verifier,
        pin_store=pin_store,
        audits=audits,
        completed=completed,
        package_coverage=package_coverage,
    )


async def _analyze_server(context: _ScanContext, idx: int, srv: ServerConfig) -> None:
    """Ordered server stages (optional stages retain their place when enabled).

    1. Connection/canary (pins already loaded), then bounded-input diagnostics.
    2. Permission analysis and optional LLM augmentation.
    3. Overrides, annotation/capability analysis, then permission scoring.
    4. Injection, SSRF, egress, then non-tool scoring. Egress consumes raw SSRF
       findings; allowlist filtering and substrate suppression happen later.
    5. Pin drift, trifecta, escalation, provenance, integrity, package and
       artifact verification. Escalation consumes the initialized pin baseline.
    6. Publish the audit and completed checks only after every stage succeeds.
    """
    opts = context.opts
    applier = context.applier
    connector = context.connector
    connection_limiter = context.connection_limiter
    analyzer = context.analyzer
    scorer = context.scorer
    llm_analyzer = context.llm_analyzer
    llm_unavailable_summary = context.llm_unavailable_summary
    injection_detector = context.injection_detector
    ssrf_detector = context.ssrf_detector
    egress_detector = context.egress_detector
    egress_server_allow = context.egress_server_allow
    pin_store = context.pin_store
    trifecta_analyzer = context.trifecta_analyzer
    escalation_analyzer = context.escalation_analyzer
    provenance_analyzer = context.provenance_analyzer
    integrity_analyzer = context.integrity_analyzer
    package_verifier = context.package_verifier
    artifact_verifier = context.artifact_verifier
    package_coverage = context.package_coverage
    audits = context.audits
    completed = context.completed
    warn = context.warn

    project_skipped = (
        srv.scope == "project" or srv.project_path is not None
    ) and not opts.connect_project_configs
    skip_connect = opts.skip_connect or project_skipped
    if project_skipped:
        launch = (
            shlex.join(cast(list[str], redact_data([srv.command, *srv.args])))
            if srv.command
            else redact_text(srv.url or "(no command or endpoint)")
        )
        warn(
            "project_config_not_connected",
            f"Project config '{redact_text(srv.name)}' not connected: {launch}. "
            "Use --connect-project-configs to opt in (unless --skip-connect).",
            check="connection",
            servers=[srv.name],
        )
    if skip_connect:
        audit = connector.skip_connect_audit(srv)
    elif opts.canary_check:
        baseline_warnings: list[ScanWarning] = []
        baseline = pin_store.canary_baseline(srv.name, warnings=baseline_warnings) if pin_store else None
        for warning in baseline_warnings:
            warn(warning.code, warning.message, check=warning.check, servers=warning.servers)
        async with connection_limiter:
            audit = await connector.connect(
                srv,
                canary_calls=opts.canary_calls,
                canary_identities=opts.canary_identities,
                canary_baseline=baseline,
                safe_tools=frozenset(
                    mark[len(srv.name) + 1 :]
                    for mark in opts.canary_safe_tools
                    if mark.startswith(srv.name + "/")
                ),
            )
        if audit.canary and audit.canary.status != "complete":
            warn(
                "canary_incomplete",
                "; ".join(audit.canary.warnings) or "Canary incomplete.",
                check="canary_check",
                servers=[srv.name],
            )
    else:
        async with connection_limiter:
            audit = await connector.connect(srv)

    if pin_store is not None:
        audit.pin_verification = pin_store.verification(srv.name)
        for warning in pin_store.verification_warnings(srv.name):
            warn(warning.code, redact_text(warning.message), check=warning.check, servers=warning.servers)
        if not pin_store.baseline_trusted(srv.name):
            assert audit.pin_verification is not None
            message = pin_store.verification_message(srv.name)
            audit.pin_integrity_findings.append(
                PinIntegrityFinding.model_validate(
                    {
                        "state": audit.pin_verification.state,
                        "server_name": srv.name,
                        "kid": audit.pin_verification.kid,
                        "summary": message,
                    }
                )
            )
            warn("pin_integrity_failed", redact_text(message), check="pin_check", servers=[srv.name])

    # Keep listed surfaces intact for hashing/reporting. Only detector
    # input is bounded; coverage loss is explicit and contains no text.
    fields: list[str] = []
    for tool in audit.tools:
        fields.extend((tool.name, tool.description or ""))
        props = tool.input_schema.get("properties", {}) if tool.input_schema else {}
        if isinstance(props, dict):
            fields.extend(str(name) for name in props)
    for prompt in audit.prompts:
        fields.extend((prompt.name, prompt.description or "", *prompt.arguments))
    for resource in audit.resources:
        fields.extend(
            (resource.uri, resource.name or "", resource.description or "", resource.mime_type or "")
        )
    truncated = sum(len(bounded_text(text)) < len(text) for text in fields)
    if truncated:
        warn(
            "description_truncated",
            f"Detector text limited to {MAX_FIELD_BYTES} UTF-8 bytes per field; "
            f"{truncated} field(s) truncated. Findings may omit suffix evidence.",
            check="permission_analysis",
            servers=[srv.name],
        )

    for target_type, target_name, text in chain(
        (("tool", tool.name, agent_visible_text(tool)) for tool in audit.tools),
        (
            ("prompt", prompt.name, prompt_visible_text(prompt))
            for prompt in audit.prompts
            if injection_detector is not None
        ),
    ):
        if text.incomplete:
            warn(
                "agent_text_incomplete",
                f"Agent-visible text scan incomplete for {target_type} {target_name!r}: "
                + "; ".join(text.incomplete),
                check="agent_visible_text",
                servers=[srv.name],
            )

    # Analyze tool list for new permission findings
    schema_incomplete: list[str] = []
    if not skip_connect or not audit.permissions:
        raw_findings = analyzer.analyze_server(audit.tools, incomplete_reasons=schema_incomplete)
    else:
        raw_findings = list(audit.permissions)
    if schema_incomplete:
        warn(
            "permission_schema_incomplete",
            "Permission schema analysis incomplete: " + "; ".join(schema_incomplete),
            check="permission_analysis",
            servers=[srv.name],
        )

    # Optional LLM augmentation for low-confidence tools
    if llm_analyzer is not None:
        llm_outcome = await llm_analyzer.analyze_server_with_status(audit.tools, raw_findings)
        audit.llm_analysis = llm_outcome.summary
        raw_findings = raw_findings + llm_outcome.findings
    elif opts.llm_analysis and llm_unavailable_summary is not None:
        audit.llm_analysis = llm_unavailable_summary.model_copy(deep=True)

    # Apply user overrides between analysis and scoring
    audit.permissions = applier.apply(srv.name, raw_findings)
    audit.annotations_missing = analyzer.annotations_missing(audit.tools)
    audit.annotation_findings = [
        finding for tool in audit.tools for finding in analyzer.analyze_annotation_contradictions(tool)
    ]
    audit.capability_findings = analyzer.analyze_capabilities(audit.prompts, audit.resources)
    tool_schema_incomplete: list[str] = []
    audit.schema_findings = [
        finding
        for tool in audit.tools
        for finding in scan_tool_schema(tool, server_url=srv.url, incomplete_reasons=tool_schema_incomplete)
    ]
    if tool_schema_incomplete:
        warn(
            "tool_schema_incomplete",
            "Tool schema analysis incomplete: " + "; ".join(tool_schema_incomplete),
            check="metadata",
            servers=[srv.name],
        )
    audit.risk_score = scorer.score_server(audit.permissions)
    # Legacy annotation contributions obey the same operator overrides.
    alert_findings = applier.apply(srv.name, raw_findings + analyzer.legacy_annotation_findings(audit.tools))
    audit.permission_alert_score = scorer.score_server(alert_findings).composite

    # Optional injection detection
    if injection_detector is not None:
        audit.injection_findings.extend(
            injection_detector.scan_server(audit.tools, audit.prompts, audit.resources)
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
        audit.drift_findings.extend(pin_store.check_drift(srv.name, audit.tools))

    # Optional trifecta per-server detection
    if trifecta_analyzer is not None:
        audit.trifecta_findings = trifecta_analyzer.analyze_server(audit)

    # Optional capability-escalation check vs the pin baseline
    if escalation_analyzer is not None and pin_store is not None:
        escalation_baseline = pin_store.baseline_tools(srv.name)
        if escalation_baseline:
            escalation_incomplete: list[str] = []
            audit.escalation_findings = escalation_analyzer.analyze_server(
                srv.name,
                escalation_baseline,
                audit.tools,
                uncovered_annotations=pin_store.legacy_tool_names(srv.name),
                incomplete_reasons=escalation_incomplete,
            )
            if escalation_incomplete:
                warn(
                    "permission_schema_incomplete",
                    "Escalation schema analysis incomplete: " + "; ".join(escalation_incomplete),
                    check="escalation_check",
                    servers=[srv.name],
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
            integrity_warnings: list[ScanWarning] = []
            audit.integrity_findings = integrity_analyzer.analyze_server(
                srv.name, baseline_artifacts, warnings=integrity_warnings
            )
            for warning in integrity_warnings:
                warn(warning.code, warning.message, check=warning.check, servers=warning.servers)

    # Optional registry package verification (network) vs the pin baseline.
    # Runs in a worker thread so the synchronous registry I/O never blocks
    # the anyio event loop.
    if package_verifier is not None and pin_store is not None:
        from mcp_audit.pkgverify import verification_coverage

        baseline_pkgs = pin_store.baseline_package_hashes(srv.name)
        verified_refs: set[str] = set()
        if baseline_pkgs:
            audit.package_verify_findings = await anyio.to_thread.run_sync(
                package_verifier.analyze_server, srv.name, srv, baseline_pkgs, verified_refs
            )
        package_coverage["verify_artifacts"][idx] = verification_coverage(srv, baseline_pkgs, verified_refs)

    # Optional byte-level artifact verification (network) vs the pin baseline.
    # Downloads + hashes off the event loop so blocking I/O never stalls anyio.
    if artifact_verifier is not None and pin_store is not None:
        from mcp_audit.pkgverify import verification_coverage

        baseline_artifact_pkgs = pin_store.baseline_artifact_hashes(srv.name)
        verified_artifact_refs: set[str] = set()
        if baseline_artifact_pkgs:
            audit.artifact_verify_findings = await anyio.to_thread.run_sync(
                artifact_verifier.analyze_server,
                srv.name,
                srv,
                baseline_artifact_pkgs,
                verified_artifact_refs,
            )
        package_coverage["download_artifacts"][idx] = verification_coverage(
            srv, baseline_artifact_pkgs, verified_artifact_refs, artifact=True
        )

    audits[idx] = audit
    completed[idx].update(("metadata", "permissions", "capabilities"))
    completed[idx].update(
        check
        for check in OPTIONAL_CHECKS
        if getattr(opts, "canary_check" if check == "runtime_security" else check) and check != "shadow_check"
    )


def _finalize_scan(context: _ScanContext) -> AuditReport:
    """Ordered fleet stages after all guarded server tasks have finished.

    Connector/LLM/baseline warnings precede SSRF suppression; egress has already
    consumed SSRF. Fleet trifecta and shadowing precede coverage construction.
    Discard failed-task package evidence, sort warnings, build the report, then
    apply finding suppression (after scoring, preserving the existing contract).
    """
    opts = context.opts
    applier = context.applier
    out = context.out
    start = context.start
    servers = context.servers
    parse_errors = context.parse_errors
    scan_warnings = context.scan_warnings
    connector = context.connector
    audits = context.audits
    completed = context.completed
    package_coverage = context.package_coverage
    pin_store = context.pin_store
    ssrf_allow = context.ssrf_allow
    trifecta_analyzer = context.trifecta_analyzer
    shadowing_analyzer = context.shadowing_analyzer
    warn = context.warn
    ssrf_suppressed = 0

    for warning in cast(list[ScanWarning], connector.scan_warnings):
        warn(warning.code, warning.message, check=warning.check, servers=warning.servers)

    # A model omission, refusal, malformed response, provider error, or detected
    # injection is coverage loss, not a clean empty result. The per-server
    # summary is authoritative; this additive warning keeps terminal and legacy
    # warning consumers from overlooking it.
    setup_reasons = {
        LLMAnalysisReasonCode.MISSING_CREDENTIAL,
        LLMAnalysisReasonCode.MISSING_DEPENDENCY,
    }
    for audit in audits:
        summary = audit.llm_analysis
        if (
            summary is not None
            and summary.status == LLMAnalysisStatus.UNKNOWN
            and summary.reason_code not in setup_reasons
        ):
            warn(
                "llm_analysis_unknown",
                f"--llm-analysis: result for {audit.server.name} is UNKNOWN "
                f"({summary.reason_code.value}); no model findings were admitted.",
                check="llm_analysis",
                servers=[audit.server.name],
            )

    # Every pin-comparison check needs a baseline; warn if asked for but nothing is pinned.
    if pin_store is not None and not pin_store.pinned_servers():
        no_baseline_checks: list[tuple[str, str, str]] = [
            (
                "escalation_check",
                "--escalation-check",
                "Run `mcp-audit pin` first to capture a baseline to compare against.",
            ),
            (
                "provenance_check",
                "--provenance-check",
                "Run `mcp-audit pin` first to capture a launch-config baseline to compare against.",
            ),
            (
                "integrity_check",
                "--integrity-check",
                "Run `mcp-audit pin` first to capture launch-artifact hashes to compare against.",
            ),
            (
                "verify_artifacts",
                "--verify-artifacts",
                "Run `mcp-audit pin --verify-artifacts` first to capture registry package hashes.",
            ),
            (
                "download_artifacts",
                "--download-artifacts",
                "Run `mcp-audit pin --download-artifacts` first to capture artifact byte-hashes.",
            ),
        ]
        # A pin file that exists but cannot be parsed is a materially different
        # (and scarier) condition than never having pinned — it can mask a wiped
        # or tampered baseline — so it gets its own code instead of folding into
        # "missing". Mutations already refuse to write through such a file.
        corrupted = pin_store.read_error
        for check_field, flag, remedy in no_baseline_checks:
            if not getattr(opts, check_field):
                continue
            if corrupted:
                warn(
                    "pin_baseline_corrupted",
                    f"{flag}: pin baseline file {pin_store.path} exists but could not "
                    f"be parsed ({corrupted}). Repair the file or re-pin; pin "
                    "mutations refuse to overwrite it.",
                    check=check_field,
                )
            else:
                warn(
                    "pin_baseline_missing",
                    f"{flag}: no pin baseline found. {remedy}",
                    check=check_field,
                )

    # A baseline withheld after failed verification (MCP027), or an
    # unauthenticated legacy v1 pin while trusted keys exist, is not a stale
    # pin: report it as withheld, never as "predates capture, re-pin".
    withheld: list[str] = []
    if pin_store is not None:
        withheld = sorted(
            {audit.server.name for audit in audits if not pin_store.baseline_usable(audit.server.name)}
        )
    if withheld:
        for check_field, flag in (
            ("pin_check", "--pin-check"),
            ("canary_check", "--canary-check"),
            ("escalation_check", "--escalation-check"),
            ("provenance_check", "--provenance-check"),
            ("integrity_check", "--integrity-check"),
            ("verify_artifacts", "--verify-artifacts"),
            ("download_artifacts", "--download-artifacts"),
        ):
            if not getattr(opts, check_field):
                continue
            warn(
                "pin_baseline_withheld",
                f"{flag}: {len(withheld)} server(s) have pin baselines that cannot be trusted "
                "(failed integrity verification, MCP027, or an unsigned legacy v1 pin while "
                f"trusted keys exist) and were not compared: {', '.join(withheld)}. "
                "Restore a signed baseline, or re-review and re-pin.",
                check=check_field,
                servers=withheld,
            )

    # Per-server staleness: a server IS pinned but its baseline predates the
    # provenance/integrity snapshot, so it is silently skipped. Surface it so the
    # user knows the check ran but found nothing to compare for those servers.
    if pin_store is not None and (
        opts.provenance_check or opts.integrity_check or opts.verify_artifacts or opts.download_artifacts
    ):
        pinned = set(pin_store.pinned_servers())
        scanned_pinned = [
            audit.server.name
            for audit in audits
            if audit.server.name in pinned and audit.server.name not in withheld
        ]
        stale_baseline_checks = [
            (
                "provenance_check",
                "--provenance-check",
                pin_store.baseline_config,
                "predate launch-config snapshots and were skipped",
                "Re-pin with `mcp-audit pin` to enable provenance comparison.",
            ),
            (
                "integrity_check",
                "--integrity-check",
                pin_store.baseline_artifacts,
                "predate artifact-hash capture and were skipped",
                "Re-pin with `mcp-audit pin` to enable integrity comparison.",
            ),
            (
                "verify_artifacts",
                "--verify-artifacts",
                pin_store.baseline_package_hashes,
                "lack captured registry hashes and were skipped",
                "Re-pin with `mcp-audit pin --verify-artifacts` to enable verification.",
            ),
            (
                "download_artifacts",
                "--download-artifacts",
                pin_store.baseline_artifact_hashes,
                "lack captured artifact byte-hashes and were skipped",
                "Re-pin with `mcp-audit pin --download-artifacts` to enable verification.",
            ),
        ]
        for check_field, flag, baseline_of, phrase, remedy in stale_baseline_checks:
            if not getattr(opts, check_field):
                continue
            stale = sorted(n for n in scanned_pinned if baseline_of(n) is None)
            if stale:
                warn(
                    "pin_baseline_stale",
                    f"{flag}: {len(stale)} pinned server(s) {phrase}: {', '.join(stale)}. {remedy}",
                    check=check_field,
                    servers=stale,
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
            terminal_safe(
                f"--ssrf-allowlist: suppressed {ssrf_suppressed} SSRF finding(s) "
                "with an allowlisted fixed target host."
            ),
            style="dim",
        )

    # Fleet-level trifecta pass — runs once after all servers are audited
    fleet_trifecta: list[TrifectaFinding] = []
    if trifecta_analyzer is not None:
        fleet_trifecta = trifecta_analyzer.analyze_fleet(audits)

    # Fleet-level shadowing pass — runs once after all servers are audited
    shadowing: list[ShadowingFinding] = []
    if shadowing_analyzer is not None:
        shadowing = shadowing_analyzer.analyze_fleet(audits)
        for checks in completed:
            if checks:
                checks.add("shadow_check")

    # A guarded failure discards its audit; previously fetched package evidence
    # must not survive as a claim that the discarded check completed.
    for index, checks in enumerate(completed):
        if not checks:
            for entries in package_coverage.values():
                entries[index] = CheckCoverage(state="not_run", reason="analysis did not complete")

    # Server tasks append warnings as they finish; keep only the report field
    # stable while preserving the console's arrival order.
    scan_warnings.sort(key=lambda warning: (tuple(sorted(warning.servers)), warning.code, warning.message))

    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname=socket.gethostname(),
        os_platform=platform.system(),
        connection_mode=(
            ConnectionMode.SKIPPED
            if opts.skip_connect or (audits and all(a.connection_status == "skipped" for a in audits))
            else ConnectionMode.ATTEMPTED
        ),
        servers_discovered=len(servers),
        servers_connected=sum(1 for a in audits if a.connection_status in ("connected", "partial")),
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
        warnings=scan_warnings,
        coverage=build_coverage(
            audits,
            requested={
                check
                for check in OPTIONAL_CHECKS
                if getattr(opts, "canary_check" if check == "runtime_security" else check)
            },
            skip_connect=opts.skip_connect,
            warnings=scan_warnings,
            completed=completed,
            package_coverage=package_coverage,
            discovery_incomplete=bool(parse_errors),
            config_health_inspected=True,
            baselines={
                check: [
                    a.server.name in pin_store.pinned_servers() and pin_store.baseline_usable(a.server.name)
                    if check == "pin_check"
                    else bool(baseline(a.server.name))
                    for a in audits
                ]
                for check, baseline in (
                    ("pin_check", pin_store.baseline_tools),
                    ("escalation_check", pin_store.baseline_tools),
                    ("provenance_check", pin_store.baseline_config),
                    ("integrity_check", pin_store.baseline_artifacts),
                    ("verify_artifacts", pin_store.baseline_package_hashes),
                    ("download_artifacts", pin_store.baseline_artifact_hashes),
                )
                if getattr(opts, check)
            }
            if pin_store is not None
            else {},
        ),
    )
    applier.suppress(report)
    return report


def _parse_extra_config(path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
    """Parse an explicitly named standalone config file.

    Raises ValueError on a missing, non-regular, unreadable, empty, unparseable,
    or unsupported config file. Malformed entries and duplicate keys become
    config-health findings while valid sibling entries are retained. Unlike
    fleet discovery (where a broken config is skipped so one bad file cannot
    void a sweep), the caller named this exact path: failing silently would let
    a typo degrade into a clean zero-finding report — the worst failure mode
    for a security scanner feeding a downstream gate. Delegates to
    :func:`mcp_audit.api.parse_config` so file-based and in-memory scans honor
    identical config-format handling and error semantics.
    """
    from mcp_audit.api import parse_config

    try:
        if not path.exists():
            raise ValueError(f"Config file not found: {path}")
        if not path.is_file():
            raise ValueError(f"Config path is not a regular file: {path}")
        servers = parse_config(
            path.read_text(encoding="utf-8-sig"), source=str(path), parse_errors=parse_errors
        )
        return [
            server.model_copy(update={"config_source": "explicit file; parsed as Claude-style config"})
            for server in servers
        ]
    except OSError as exc:
        raise ValueError(f"Failed to read {path}: {redact_text(str(exc))}") from exc
    except UnicodeError as exc:
        raise ValueError(f"Failed to read {path}: invalid UTF-8 encoding") from exc
    except ValueError as exc:
        raise ValueError(f"Failed to parse {path}: {redact_text(str(exc))}") from exc
