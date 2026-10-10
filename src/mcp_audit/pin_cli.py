"""CLI adapter for pin creation, review, and cleanup commands."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from mcp_audit.pkgverify import ArtifactCapture, ArtifactVerifier, PackageVerifier

import anyio
import click
from rich.console import Console
from rich.text import Text

from mcp_audit.confighealth import duplicate_server_config_counts
from mcp_audit.discovery import discover_all_configs
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import (
    DriftFinding,
    DriftStatus,
    EscalationFinding,
    ProtocolObservation,
    ProvenanceFinding,
    ServerAudit,
    ServerConfig,
)
from mcp_audit.report import error_console
from mcp_audit.terminal_text import strip_controls, terminal_safe

console = Console()

_UNVERIFIED_LEGACY_NOTE = (
    "Compared against an unverified legacy (v1) baseline: trusted pin keys exist but nothing "
    "authenticates this entry. Review before signing."
)


class _PinServerOptions(TypedDict, total=False):
    redact_args: bool
    protocol: ProtocolObservation


# ---------------------------------------------------------------------------
# pin subcommand
# ---------------------------------------------------------------------------


@click.group("pin", invoke_without_command=True)
@click.pass_context
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
@click.option(
    "--no-redact-args",
    is_flag=True,
    default=False,
    help="Store raw launch arguments, including secrets, in the pin file.",
)
@click.option("--unsigned", is_flag=True, default=False, help="Explicitly write pins without signatures.")
@click.option(
    "--signing-key",
    envvar="MCP_AUDIT_PIN_KEY",
    default=None,
    metavar="PATH",
    help="Signing key path (or MCP_AUDIT_PIN_KEY); CI can verify with public keys only.",
)
@click.option("--config", "extra_config", default=None, metavar="PATH", help="Use an additional MCP config.")
@click.option(
    "--config-only",
    is_flag=True,
    default=False,
    help="Use only --config and do not discover workstation MCP configs.",
)
def pin_command(
    ctx: click.Context,
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
    no_redact_args: bool,
    unsigned: bool,
    signing_key: str | None,
    extra_config: str | None,
    config_only: bool,
) -> None:
    """Pin tool schemas for drift detection on subsequent scans."""
    if config_only and not extra_config:
        raise click.UsageError("--config-only requires --config.")

    if ctx.invoked_subcommand is not None:
        if any((server_name, clear_server, clear_stale, status, stale, refresh_server, apply_refresh)):
            raise click.UsageError("Pin actions cannot be combined with a pin subcommand.")
        if unsigned:
            raise click.UsageError("--unsigned applies only to pin writes, not key-management commands.")
        if ctx.invoked_subcommand == "rotate-key":
            from mcp_audit.pinning import DEFAULT_PIN_PATH, PinStore

            ctx.obj = PinStore(
                path=Path(pin_file) if pin_file else DEFAULT_PIN_PATH,
                signing_key=Path(signing_key) if signing_key else None,
                unsigned=unsigned,
            )
        return

    from mcp_audit.pin_signing import PinSigningError
    from mcp_audit.pinning import DEFAULT_PIN_PATH, PinFileError, PinStore

    store_path = Path(pin_file) if pin_file else DEFAULT_PIN_PATH
    if signing_key is None and not unsigned:
        store = PinStore(path=store_path)
    else:
        store = PinStore(
            path=store_path,
            signing_key=Path(signing_key) if signing_key else None,
            unsigned=unsigned,
        )

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
            console.print(terminal_safe(f"Removed pins for server '{clear_server}'."), style="green")
            return

        if status:
            _render_pin_status(store, json_status)
            return

        if stale:
            _render_pin_stale(store, json_status, extra_config, config_only)
            return

        if clear_stale:
            _render_pin_clear_stale(store, json_status, apply_refresh, extra_config, config_only)
            return

        if refresh_server:
            refresh_args = (
                refresh_server,
                store,
                apply_refresh,
                json_status,
                verify_artifacts,
                download_artifacts,
                not no_redact_args,
            )
            if extra_config is not None or config_only:
                anyio.run(_run_pin_refresh, *refresh_args, extra_config, config_only)
            else:
                anyio.run(_run_pin_refresh, *refresh_args)
            return

        # Pin servers
        run_args = (
            server_name,
            store,
            verify_artifacts,
            download_artifacts,
            not no_redact_args,
        )
        if extra_config is not None or config_only:
            anyio.run(_run_pin, *run_args, extra_config, config_only)
        else:
            anyio.run(_run_pin, *run_args)
    except PinFileError as exc:
        # Mutations refuse to write through an unparseable pin file — wiping a
        # repairable baseline is worse than failing loudly.
        error_console.print(terminal_safe(f"{exc}. Fix or remove the file, then re-run."), style="red")
        raise SystemExit(1) from exc
    except PinSigningError as exc:
        error_console.print(terminal_safe(str(exc)), style="red")
        raise SystemExit(1) from exc


@pin_command.command("keygen")
def pin_keygen() -> None:
    """Create a local Ed25519 signing key and trust its public key."""
    from mcp_audit.pin_signing import PinSigningError, generate_keypair

    try:
        generated = generate_keypair()
    except (OSError, ValueError, PinSigningError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Created signing key {generated.kid}.")
    click.echo(f"Public key: {generated.public_key}")


@pin_command.command("rotate-key")
@click.option("--grace-days", type=click.IntRange(min=0, max=3650), default=30, show_default=True)
@click.option(
    "--resign", is_flag=True, help="Re-sign existing pins with the current key without rotating it."
)
@click.pass_obj
def pin_rotate_key(store: object, grace_days: int, resign: bool) -> None:
    """Rotate the signing key and retain the previous key for a grace period."""
    from mcp_audit.pin_signing import PinSigningError
    from mcp_audit.pinning import PinStore as PS

    try:
        if not isinstance(store, PS):
            raise click.ClickException("Pin store was not initialized.")
        public_key = store.resign() if resign else store.rotate_key(grace_days)
    except (OSError, ValueError, PinSigningError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "Re-signed pins with the current key." if resign else f"Rotated signing key ({grace_days}-day grace)."
    )
    click.echo(f"Public key: {public_key}")


@pin_command.command("trust-key")
@click.option("--add", "public_key", required=True, metavar="PUBLICHEX", help="Trust this raw public key.")
def pin_trust_key(public_key: str) -> None:
    """Add an externally supplied public key to the local trust store."""
    from mcp_audit.pin_signing import PinSigningError, trust_key

    try:
        kid = trust_key(public_key)
    except (OSError, ValueError, PinSigningError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Trusted signing key {kid}.")


async def _run_pin(
    server_name: str | None,
    store: object,
    verify_artifacts: bool = False,
    download_artifacts: bool = False,
    redact_args: bool = True,
    extra_config: str | None = None,
    config_only: bool = False,
) -> None:
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await run_scan(
        ScanOptions(extra_config=extra_config, config_only=config_only),
        override_applier=override_applier,
        console=console,
    )
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
                console.print(terminal_safe(_ambiguous_pin_message(audit.server.name)), style="yellow")
                skipped_ambiguous.add(audit.server.name)
            continue
        if audit.connection_status != "connected":
            console.print(
                terminal_safe(
                    f"Skipped '{audit.server.name}': connection {audit.connection_status}."
                    " Use scan --skip-connect for config-only review; pins require live tool schemas."
                ),
                style="yellow",
            )
            continue
        pkg_hashes = await anyio.to_thread.run_sync(verifier.capture, audit.server) if verifier else None
        art_capture = await _capture_artifacts(artifact_verifier, audit.server)
        for warning in art_capture.warnings:
            console.print(terminal_safe(warning), style="yellow")
        art_hashes = art_capture.hashes
        pin_options: _PinServerOptions = {"redact_args": redact_args}
        if audit.protocol is not None:
            pin_options["protocol"] = audit.protocol
        store.pin_server(
            audit.server.name,
            audit.tools,
            audit.server,
            pkg_hashes or None,
            art_hashes or None,
            **pin_options,
        )
        suffix = ""
        if pkg_hashes:
            suffix += f" (+{len(pkg_hashes)} registry hash(es))"
        if art_hashes:
            suffix += f" (+{len(art_hashes)} artifact byte-hash(es))"
        console.print(
            terminal_safe(f"Pinned {len(audit.tools)} tool(s) for '{audit.server.name}'{suffix}."),
            style="green",
        )

    if server_name and not matched:
        error_console.print(
            terminal_safe(f"Server '{server_name}' not found — nothing was pinned."), style="red"
        )
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
    redact_args: bool = True,
    extra_config: str | None = None,
    config_only: bool = False,
) -> None:
    """Review drift for one server and optionally refresh its pin baseline."""
    from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
    from mcp_audit.pinning import PinStore as PS
    from mcp_audit.pkgverify import ArtifactCapture

    assert isinstance(store, PS)
    verifier, artifact_verifier = _make_registry_verifiers(verify_artifacts, download_artifacts)
    override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
    report = await run_scan(
        ScanOptions(extra_config=extra_config, config_only=config_only),
        override_applier=override_applier,
        console=console,
    )

    matching_audits = [audit for audit in report.audits if audit.server.name == server_name]
    if not matching_audits:
        if json_status:
            click.echo(_pin_refresh_json(server_name, 0, [], applied=False, error="server not found"))
            return
        console.print(terminal_safe(f"Server '{server_name}' not found."), style="yellow")
        return
    if len(matching_audits) > 1:
        error = _ambiguous_pin_message(server_name)
        if json_status:
            click.echo(_pin_refresh_json(server_name, 0, [], applied=False, error=error))
            return
        console.print(terminal_safe(error), style="yellow")
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
            terminal_safe(
                f"Skipped '{audit.server.name}': connection {audit.connection_status}."
                " Pin refresh requires live tool schemas."
            ),
            style="yellow",
        )
        return

    if not store.baseline_trusted(audit.server.name):
        verification_error = store.verification_message(audit.server.name)
        if not verification_error:
            verification_error = f"Pin for {audit.server.name} failed signature verification."
        if json_status:
            click.echo(
                _pin_refresh_json(
                    audit.server.name,
                    len(audit.tools),
                    [],
                    applied=False,
                    error=verification_error,
                )
            )
        else:
            error_console.print(terminal_safe(verification_error), style="red")
        return

    # Review must show the comparison even when scans withhold the baseline:
    # an unauthenticated legacy v1 pin is compared and clearly labeled.
    unverified_legacy = store.unverified_legacy_baseline(audit.server.name)
    baseline_note = _UNVERIFIED_LEGACY_NOTE if unverified_legacy else None
    findings = store.check_drift(audit.server.name, audit.tools, review_unverified_legacy=True)
    uncovered_fields = store.uncovered_field_rows(audit.server.name, audit.tools)
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
            pin_options: _PinServerOptions = {"redact_args": redact_args}
            if audit.protocol is not None:
                pin_options["protocol"] = audit.protocol
            store.pin_server(
                audit.server.name,
                audit.tools,
                audit.server,
                refresh_pkgs or None,
                refresh_artifacts or None,
                **pin_options,
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
                uncovered_fields=uncovered_fields,
                baseline_note=baseline_note,
            )
        )
        return

    for warning in art_capture.warnings:
        console.print(terminal_safe(warning), style="yellow")

    _render_pin_refresh_review(
        audit.server.name,
        len(audit.tools),
        findings,
        escalation_findings,
        provenance_findings,
        baseline_note=baseline_note,
    )
    if uncovered_fields:
        from rich.table import Table

        table = Table("Tool", "Field", "Review note")
        for row in uncovered_fields:
            table.add_row(terminal_safe(row["tool_name"]), row["field"], row["summary"])
        console.print(table)

    if not apply_refresh:
        console.print(
            "[yellow]Review complete; no pins were changed. Rerun with --apply to refresh.[/yellow]"
        )
        return

    final_pin_options: _PinServerOptions = {"redact_args": redact_args}
    if audit.protocol is not None:
        final_pin_options["protocol"] = audit.protocol
    store.pin_server(
        audit.server.name,
        audit.tools,
        audit.server,
        refresh_pkgs or None,
        refresh_artifacts or None,
        **final_pin_options,
    )
    console.print(
        terminal_safe(f"Refreshed {len(audit.tools)} pin(s) for '{audit.server.name}'."), style="green"
    )


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

    baseline_tools = store.baseline_tools(audit.server.name, review_unverified_legacy=True)
    if baseline_tools:
        escalation_findings = EscalationAnalyzer().analyze_server(
            audit.server.name,
            baseline_tools,
            audit.tools,
            uncovered_annotations=store.legacy_tool_names(audit.server.name),
        )

    baseline_config = store.baseline_config(audit.server.name, review_unverified_legacy=True)
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
    uncovered_fields: list[dict[str, str]] | None = None,
    baseline_note: str | None = None,
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
        "uncovered_fields": uncovered_fields or [],
        # Additive: false when the compared baseline could not be verified.
        "baseline_verified": baseline_note is None,
        "baseline_note": baseline_note,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _render_pin_refresh_review(
    server_name: str,
    tool_count: int,
    drift_findings: list[DriftFinding],
    escalation_findings: list[EscalationFinding] | None = None,
    provenance_findings: list[ProvenanceFinding] | None = None,
    *,
    baseline_note: str | None = None,
) -> None:
    from rich.table import Table

    escalation_findings = escalation_findings or []
    provenance_findings = provenance_findings or []
    counts = {status: 0 for status in DriftStatus}
    for finding in drift_findings:
        counts[finding.status] += 1

    console.print(
        Text.assemble(
            ("Pin refresh review:", "bold"), terminal_safe(f" {server_name} ({tool_count} current tool(s))")
        )
    )
    if baseline_note is not None:
        console.print(terminal_safe(baseline_note), style="bold yellow")
    if not (drift_findings or escalation_findings or provenance_findings):
        if baseline_note is not None:
            console.print(
                "[yellow]The pin baseline could not be verified; no differences from the unverified "
                "legacy baseline were found. Review the current tools before signing.[/yellow]"
            )
            return
        console.print("[green]No drift found. Current tools already match the pin baseline.[/green]")
        return

    if drift_findings:
        console.print(
            terminal_safe(
                f"{counts[DriftStatus.NEW]} new, {counts[DriftStatus.CHANGED]} changed, "
                f"{counts[DriftStatus.REMOVED]} removed"
            ),
            style="yellow",
        )

        table = Table(show_header=True)
        table.add_column("Status", style="yellow")
        table.add_column("Tool", style="cyan")
        table.add_column("Review note")

        for finding in drift_findings:
            table.add_row(
                terminal_safe(finding.status.value),
                terminal_safe(finding.tool_name),
                terminal_safe(finding.summary or ", ".join(finding.details) or "Review before refreshing."),
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

    console.print(
        Text.assemble((strip_controls(heading), "bold red"), " — review before refreshing the baseline:")
    )
    table = Table(show_header=True)
    table.add_column("Rule", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Target", style="cyan")
    table.add_column("What changed")
    for rule_id, severity, target, detail in rows:
        table.add_row(
            terminal_safe(rule_id), terminal_safe(severity), terminal_safe(target), terminal_safe(detail)
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
                    **store.signing_status(status.server_name),
                }
                for status in statuses
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(
        Text.assemble(("Pin baseline:", "bold"), f" {len(statuses)} server(s), {total_tools} tool(s)")
    )
    console.print(terminal_safe(f"Pin file: {store.path}"), style="dim")

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
    table.add_column("Schema")
    table.add_column("Signed")
    table.add_column("Key ID")
    table.add_column("Verification")

    for status in statuses:
        signing = store.signing_status(status.server_name)
        table.add_row(
            terminal_safe(status.server_name),
            terminal_safe(str(status.tool_count)),
            terminal_safe(_datetime_or_unknown(status.oldest_pinned_at)),
            terminal_safe(_datetime_or_unknown(status.newest_pinned_at)),
            terminal_safe(_pin_age(status.newest_pinned_at)),
            terminal_safe(str(signing.get("schema", "unknown"))),
            terminal_safe(str(signing.get("signed", False))),
            terminal_safe(str(signing.get("kid") or "—")),
            terminal_safe(_status_verification(signing)),
        )

    console.print(table)
    for status in statuses:
        public_key = store.signing_status(status.server_name).get("trusted_public_key")
        if (
            isinstance(public_key, str)
            and len(public_key) == 64
            and all(c in "0123456789abcdef" for c in public_key)
        ):
            # Plain output keeps a copyable CI key intact on narrow terminals.
            click.echo(f"Trusted public key for {strip_controls(status.server_name)} (CI): {public_key}")


def _status_verification(signing: dict[str, object]) -> str:
    state = signing.get("verification")
    label = str(state) if state else "none"
    if signing.get("baseline_usable") is False:
        label += " (withheld)"
    return label


def _configured_pin_server_names(extra_config: str | None, config_only: bool) -> set[str]:
    from mcp_audit.engine import _parse_extra_config

    if config_only:
        configs = []
    else:
        configs = discover_all_configs(None)
    if extra_config:
        try:
            configs.extend(_parse_extra_config(Path(extra_config)))
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    return {server.name for server in configs}


def _render_pin_stale(
    store: object, json_status: bool, extra_config: str | None = None, config_only: bool = False
) -> None:
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    discovered_names = _configured_pin_server_names(extra_config, config_only)
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

    console.print(
        Text.assemble(
            ("Stale pin baselines:", "bold"), f" {len(stale)} server(s) not found in current configs"
        )
    )
    console.print(terminal_safe(f"Pin file: {store.path}"), style="dim")

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
            terminal_safe(status.server_name),
            terminal_safe(str(status.tool_count)),
            terminal_safe(_datetime_or_unknown(status.newest_pinned_at)),
            terminal_safe(_pin_age(status.newest_pinned_at)),
            terminal_safe(status.remediation),
        )

    console.print(table)
    console.print("[yellow]Review only; no pins were changed.[/yellow]")


def _render_pin_clear_stale(
    store: object,
    json_status: bool,
    apply_clear: bool,
    extra_config: str | None = None,
    config_only: bool = False,
) -> None:
    from mcp_audit.pinning import PinStore as PS

    assert isinstance(store, PS)
    discovered_names = _configured_pin_server_names(extra_config, config_only)
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

    console.print(Text.assemble(("Stale pin cleanup review:", "bold"), f" {len(stale)} server(s) not found"))
    console.print(terminal_safe(f"Pin file: {store.path}"), style="dim")

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
            terminal_safe(status.server_name),
            terminal_safe(str(status.tool_count)),
            terminal_safe(_datetime_or_unknown(status.newest_pinned_at)),
            terminal_safe(_pin_age(status.newest_pinned_at)),
        )

    console.print(table)

    if not apply_clear:
        console.print("[yellow]Review complete; no pins were changed. Rerun with --apply to clear.[/yellow]")
        return

    console.print(terminal_safe(f"Removed {len(removed_names)} stale server baseline(s)."), style="green")


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
