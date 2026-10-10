"""Legacy scan CLI output and policy adapter; the engine remains library-only."""

from __future__ import annotations

import io
from pathlib import Path

import click
import yaml
from rich.console import Console

from mcp_audit.artifact_paths import validate_artifact_paths
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ClientType
from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config
from mcp_audit.redaction import redact_text
from mcp_audit.report import ReportGenerator, error_console
from mcp_audit.terminal_text import strip_controls, terminal_safe


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
    canary_check: bool = False,
    canary_calls: int = 5,
    canary_safe_tools: tuple[str, ...] = (),
    sarif_profile: str = "compatibility",
    max_concurrency: int = 32,
    connect_project_configs: bool = False,
    canary_identities: int | None = None,
    show_host: bool = False,
    details: bool = False,
    color: str = "auto",
    ignore_rules: tuple[str, ...] = (),
    ignore_reason: str | None = None,
    card: Path | None = None,
    names: bool = False,
    previous: Path | None = None,
    pin_file: Path | None = None,
    max_frame_bytes: int = 16 * 1024 * 1024,
    max_surface_bytes: int = 64 * 1024 * 1024,
    sdk_stdio_fallback: bool = False,
) -> None:
    """CLI scan entrypoint — calls the engine's run_scan then renders output."""
    from mcp_audit.checkup import generate_card, load_previous, sticker
    from mcp_audit.terminal_summary import summary_console

    out = summary_console(color=color)
    diagnostics = io.StringIO()
    if (names or previous is not None) and card is None:
        raise click.UsageError("--names and --previous require --card.")
    try:
        previous_report = load_previous(previous)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Cannot load previous report: {type(exc).__name__}") from None
    if config_only and not extra_config:
        raise click.ClickException("--config-only requires --config PATH.")
    if canary_check and (skip_connect or not config_only or not extra_config):
        raise click.ClickException("--canary-check requires --config PATH --config-only and a connection.")

    cfg_path = Path(override_config_path) if override_config_path else DEFAULT_OVERRIDE_PATH
    from mcp_audit.suppressions import apply_suppressions, validate_ignore_rule

    try:
        for rule in ignore_rules:
            validate_ignore_rule(rule)
        override_applier = OverrideApplier(load_override_config(cfg_path))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise click.ClickException(f"Cannot load finding overrides: {type(exc).__name__}") from None
    client_list = _parse_clients(clients)

    # Load the policy up front so its egress_allowlist / multi_tenant_hosts can configure
    # the egress detector; CLI flags merge with the policy-supplied hosts.
    policy = None
    if policy_path:
        from mcp_audit.policy import load_policy

        try:
            policy = load_policy(Path(policy_path))
        except Exception as exc:
            error_console.print(
                terminal_safe(f"Failed to load policy {policy_path}: {redact_text(str(exc))}"), style="red"
            )
            raise SystemExit(1) from exc

    scan_options = ScanOptions(
        max_concurrency=max_concurrency,
        max_frame_bytes=max_frame_bytes,
        max_surface_bytes=max_surface_bytes,
        sdk_stdio_fallback=sdk_stdio_fallback,
        canary_check=canary_check,
        canary_calls=canary_calls,
        canary_identities=canary_identities,
        canary_safe_tools=canary_safe_tools,
        skip_connect=skip_connect,
        connect_project_configs=connect_project_configs,
        config_only=config_only,
        clients=client_list,
        timeout=timeout,
        extra_config=extra_config,
        inject_check=inject_check,
        ssrf_check=ssrf_check,
        egress_check=egress_check,
        pin_check=pin_check,
        pin_file=pin_file,
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
    config_paths: list[Path] = [cfg_path]
    if policy_path:
        config_paths.append(Path(policy_path))
    if previous is not None:
        config_paths.append(previous)
    if pin_file is not None:
        config_paths.append(pin_file)
    try:
        report = await run_scan(
            scan_options,
            override_applier=override_applier,
            console=Console(file=diagnostics, force_terminal=False),
            config_paths=config_paths if json_output or sarif_output or html_output or card else None,
        )
    except ValueError as exc:
        # A caller-supplied --config path that is missing or unparseable must be
        # a hard error, not a silently-empty scan that passes downstream gates.
        raise click.ClickException(strip_controls(str(exc))) from exc

    validate_artifact_paths(
        [
            ("--json", Path(json_output) if json_output else None),
            ("--sarif", Path(sarif_output) if sarif_output else None),
            ("--html", Path(html_output) if html_output else None),
            ("--card", card),
        ],
        config_paths,
    )

    apply_suppressions(report, cli_rules=ignore_rules, cli_reason=ignore_reason)
    if policy is not None:
        from mcp_audit.policy import evaluate_policy

        selected_pin_store = None
        if (
            policy.required_pin_servers
            or policy.fail_on_pin_integrity
            or any(rule.require_pin for rule in policy.server_rules.values())
        ):
            from mcp_audit.pinning import PinStore

            selected_pin_store = PinStore(path=pin_file) if pin_file is not None else PinStore()
        report.policy_result = evaluate_policy(report, policy, pin_store=selected_pin_store)

    gen = ReportGenerator(console=out)
    gen.render_terminal(report, verbose=verbose, details=details, explicit_config=config_only)
    if diagnostics.getvalue():
        out.print(terminal_safe(diagnostics.getvalue().rstrip()))

    # Field-report mode scrubs host/username identifiers from shared artifacts.
    # Terminal output keeps real values for local readability.
    out_report = report.redacted(identifiers=True) if redact else report
    written_artifacts: list[str] = []

    if json_output:
        json_path = Path(json_output)
        gen.render_json(out_report, json_path)
        written_artifacts.append(json_path.name)

    if sarif_output:
        import json as _json

        from mcp_audit.sarif import SarifGenerator

        sarif_doc = SarifGenerator().generate(out_report, profile=sarif_profile)
        sarif_path = Path(sarif_output)
        sarif_path.write_text(_json.dumps(sarif_doc, indent=2))
        written_artifacts.append(sarif_path.name)

    if html_output:
        from mcp_audit.htmlreport import HtmlReportGenerator

        html_path = Path(html_output)
        html_path.write_text(HtmlReportGenerator().generate(out_report, show_host=show_host))
        written_artifacts.append(html_path.name)

    if card is not None:
        try:
            card.write_text(generate_card(report, names=names, previous=previous_report), encoding="utf-8")
        except OSError as exc:
            raise click.ClickException(f"Cannot write checkup card: {type(exc).__name__}") from None
        out.print(terminal_safe(sticker(report)))
        written_artifacts.append(card.name)

    if written_artifacts:
        out.print(terminal_safe(f"Wrote {' · '.join(written_artifacts)}"))

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
            error_console.print(terminal_safe(f"Unknown client '{part}'. Valid values: {valid}"), style="red")
            raise SystemExit(1) from None
    return result or None
