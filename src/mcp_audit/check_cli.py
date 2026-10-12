"""Safe review entry points; the legacy scan interface remains independent."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import ParamSpec, TypeVar

import anyio
import click
import yaml
from rich.console import Console

from mcp_audit.artifact_paths import validate_artifact_paths
from mcp_audit.checkup import generate_card, load_previous, sticker
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ClientType
from mcp_audit.report import ReportGenerator
from mcp_audit.review_discovery import review_sources, server_identity
from mcp_audit.scan_cli import _merge_host_args
from mcp_audit.terminal_summary import summary_console
from mcp_audit.terminal_text import strip_controls, terminal_safe

P = ParamSpec("P")
T = TypeVar("T")

_CLIENT_CHOICES = tuple(
    dict.fromkeys(
        spelling for client in ClientType for spelling in (client.value, client.value.replace("_", "-"))
    )
)


def _parse_client_options(
    ctx: click.Context, param: click.Parameter, values: tuple[str, ...]
) -> tuple[ClientType, ...]:
    del ctx, param
    return tuple(dict.fromkeys(ClientType(value.replace("-", "_")) for value in values))


class _RecoveryError(click.ClickException):
    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code  # type: ignore[misc]  # click declares a ClassVar; per-error codes are intended


def _recovery_error(
    failed: str,
    where: str,
    recovery: str,
    *,
    scanned: bool,
    written: tuple[Path, ...] = (),
    exit_code: int = 1,
) -> _RecoveryError:
    written_state = ", ".join(str(path) for path in written) if written else "none"
    return _RecoveryError(
        f"What failed: {failed}\nWhere: {where}\nRecovery: {recovery}\n"
        f"Scanned: {'yes' if scanned else 'no'}\nWritten: {written_state}\nExit code: {exit_code}",
        exit_code=exit_code,
    )


def _source_options(command: Callable[P, T]) -> Callable[P, T]:
    for option in (
        click.option(
            "--config",
            type=click.Path(path_type=Path),
            help="Review this explicit file only; parsed as Claude-style config.",
        ),
        click.option(
            "--include-discovered", is_flag=True, help="Also read supported client config locations."
        ),
        click.option(
            "--project", type=click.Path(path_type=Path), help="Select project scope (default: cwd)."
        ),
        click.option(
            "--client",
            "clients",
            multiple=True,
            type=click.Choice(_CLIENT_CHOICES),
            callback=_parse_client_options,
            help="Limit discovery to this client; repeat to select more than one.",
        ),
        click.option("--details", is_flag=True, help="Show full findings and source coverage."),
    ):
        command = option(command)
    return command


def _analysis_options(command: Callable[P, T]) -> Callable[P, T]:
    for option in (
        click.option("--inject-check", is_flag=True, help="Check metadata for instruction-shaped text."),
        click.option("--ssrf-check", is_flag=True, help="Flag caller-controlled fetch targets."),
        click.option("--ssrf-allowlist", metavar="HOSTS", help="Comma-separated trusted fixed-target hosts."),
        click.option(
            "--egress-check", is_flag=True, help="Audit outbound destinations; includes SSRF analysis."
        ),
        click.option("--egress-allowlist", metavar="HOSTS", help="Comma-separated trusted egress hosts."),
        click.option(
            "--multi-tenant-hosts", metavar="HOSTS", help="Extra multi-tenant hosts for egress analysis."
        ),
        click.option("--pin-check", is_flag=True, help="Check tool schema drift against stored pins."),
        click.option(
            "--trifecta-check", is_flag=True, help="Detect per-server and fleet toxic-flow exposure."
        ),
        click.option("--shadow-check", is_flag=True, help="Detect cross-server tool-name shadowing."),
        click.option("--escalation-check", is_flag=True, help="Check capability escalation against pins."),
        click.option("--provenance-check", is_flag=True, help="Check launch-config drift against pins."),
        click.option("--integrity-check", is_flag=True, help="Check on-disk launch-artifact hash drift."),
        click.option(
            "--verify-artifacts", is_flag=True, help="Network: verify registry hashes against pins."
        ),
        click.option(
            "--download-artifacts", is_flag=True, help="Network: download and verify package bytes."
        ),
        click.option("--llm-analysis", is_flag=True, help="LLM classification (requires ANTHROPIC_API_KEY)."),
        click.option(
            "--canary-check", is_flag=True, help="Exercise connected explicit-config servers for drift."
        ),
        click.option(
            "--canary-calls",
            default=5,
            type=click.IntRange(1, 100),
            show_default=True,
            help="Maximum benign exercise calls per server.",
        ),
        click.option(
            "--canary-identities",
            type=click.IntRange(1, 2),
            metavar="N",
            help="Canary identities; default 2 for stdio, 1 for HTTP/SSE.",
        ),
        click.option(
            "--canary-safe-tool",
            "canary_safe_tools",
            multiple=True,
            metavar="SERVER/TOOL",
            help="Mark an empty-argument tool safe; destructive hints still veto calls.",
        ),
        click.option(
            "--timeout",
            default=10,
            show_default=True,
            help="Per-server session budget in seconds; excludes queue wait.",
        ),
        click.option(
            "--max-concurrency",
            default=32,
            type=click.IntRange(min=1),
            show_default=True,
            help="Maximum simultaneous server sessions.",
        ),
        click.option(
            "--connect-project-configs",
            is_flag=True,
            help="Include project-scope servers in --connect-all; --connect selects one identity.",
        ),
        click.option("--skip-connect", is_flag=True, hidden=True),
        click.option("--config-only", is_flag=True, hidden=True),
        click.option("--verbose", is_flag=True, help="Show per-tool permission details."),
        click.option("--redact", is_flag=True, help="Scrub identifiers from JSON, SARIF and HTML artifacts."),
        click.option(
            "--sarif-profile",
            type=click.Choice(["compatibility", "extended"]),
            default="compatibility",
            help="Extended SARIF includes configuration-health findings.",
        ),
    ):
        command = option(command)
    return command


def _print_sources(out: Console, paths: list[tuple[str, str]]) -> None:
    for path, status in paths:
        out.print(terminal_safe(f"{status}: {path}"))
    out.print("Unsupported source: Codex (no adapter). No recursive search or config includes.")
    out.print("Project and workstation entries are listed separately; no client precedence is inferred.")


@click.command()
@_source_options
@_analysis_options
@click.option("--connect", is_flag=True, help="Connect only to the explicitly selected server identity.")
@click.option(
    "--connect-all", is_flag=True, help="Connect to the reviewed fleet; project servers require opt-in."
)
@click.option("--server", "server_id", metavar="CLIENT:SCOPE:NAME", help="Exact identity from inspect.")
@click.option("--json", "json_stdout", is_flag=True, help="Emit only AuditReport JSON on stdout.")
@click.option("--output-json", type=click.Path(path_type=Path), help="Write AuditReport JSON to FILE.")
@click.option("--sarif", type=click.Path(path_type=Path), help="Write SARIF to FILE.")
@click.option("--html", type=click.Path(path_type=Path), help="Write offline HTML to FILE.")
@click.option("--card", type=click.Path(path_type=Path), help="Write a local counts-only HTML checkup card.")
@click.option("--names", is_flag=True, help="Opt in to server names on the checkup card only.")
@click.option(
    "--previous", type=click.Path(path_type=Path), help="Compare the card with this local report JSON."
)
@click.option("--show-host", is_flag=True, help="Include the hostname in HTML (hidden by default).")
@click.option("--policy", type=click.Path(path_type=Path), help="Evaluate this explicit local policy.")
@click.option(
    "--pin-file", type=click.Path(path_type=Path), help="Use this pin baseline for detectors and policy."
)
@click.option(
    "--pin-min-sequence",
    type=click.IntRange(min=1),
    help="Require a trusted signed pin manifest at or above this sequence (policy exit 2 on failure).",
)
@click.option(
    "--override-config",
    type=click.Path(path_type=Path),
    help="Permission overrides and ignores YAML (default for discovery: ~/.mcp-audit.yaml).",
)
@click.option(
    "--ignore", "ignore_rules", multiple=True, metavar="MCP0xx", help="Ignore a finding rule for this run."
)
@click.option("--ignore-reason", help="Reason for one-run ignores (required for HIGH findings).")
@click.option("--color", type=click.Choice(["auto", "always", "never"]), default="auto", show_default=True)
@click.option(
    "--max-frame-bytes",
    default=16 * 1024 * 1024,
    type=click.IntRange(min=1),
    show_default=True,
    help="Maximum stdio frame bytes before JSON parsing (ignored with --sdk-stdio-fallback).",
)
@click.option(
    "--max-surface-bytes",
    default=64 * 1024 * 1024,
    type=click.IntRange(min=1),
    show_default=True,
    help="Total serialized listing bytes across surfaces and pages per listing round.",
)
@click.option(
    "--sdk-stdio-fallback",
    is_flag=True,
    help="Temporary SDK stdio reader compatibility mode; disables the frame cap.",
)
def check(
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    clients: tuple[ClientType, ...],
    details: bool,
    connect: bool,
    connect_all: bool,
    server_id: str | None,
    json_stdout: bool,
    output_json: Path | None,
    sarif: Path | None,
    html: Path | None,
    show_host: bool,
    policy: Path | None,
    pin_file: Path | None,
    pin_min_sequence: int | None,
    color: str,
    override_config: Path | None,
    ignore_rules: tuple[str, ...],
    ignore_reason: str | None,
    card: Path | None,
    names: bool,
    previous: Path | None,
    max_frame_bytes: int,
    max_surface_bytes: int,
    sdk_stdio_fallback: bool,
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
    canary_check: bool,
    canary_calls: int,
    canary_identities: int | None,
    canary_safe_tools: tuple[str, ...],
    timeout: int,
    max_concurrency: int,
    connect_project_configs: bool,
    skip_connect: bool,
    config_only: bool,
    verbose: bool,
    redact: bool,
    sarif_profile: str,
) -> None:
    """Review configs statically; runtime security is not checked by default."""
    if connect_all and (connect or server_id):
        raise click.UsageError("--connect-all cannot be combined with --connect or --server.")
    connecting = connect or connect_all
    if connect_project_configs and not connecting:
        raise click.UsageError("--connect-project-configs requires --connect or --connect-all.")
    if skip_connect and connecting:
        raise click.UsageError("--skip-connect cannot be combined with --connect or --connect-all.")
    if config_only and (config is None or include_discovered):
        raise click.UsageError(
            "--config-only requires --config and cannot be combined with --include-discovered."
        )
    if canary_check and (not connecting or config is None or include_discovered):
        raise click.UsageError(
            "--canary-check requires --config FILE and --connect --server or --connect-all, "
            "without discovery."
        )
    if connect and not server_id:
        raise _recovery_error(
            "--connect requires a selected server identity",
            "command options",
            "run mcp-audit inspect, then pass --connect --server CLIENT:SCOPE:NAME",
            scanned=False,
        )
    if server_id and not connect:
        raise _recovery_error(
            "--server requires --connect",
            "command options",
            "run mcp-audit check --connect --server CLIENT:SCOPE:NAME",
            scanned=False,
        )
    if (names or previous is not None) and card is None:
        raise _recovery_error(
            "--names and --previous require --card",
            "command options",
            "add --card FILE or remove --names and --previous",
            scanned=False,
            exit_code=2,
        )
    out = summary_console(color=color, stderr=json_stdout)
    scanned = False
    written: list[Path] = []
    stage = "input validation"
    try:
        from mcp_audit.overrides import OverrideApplier, OverrideConfig, load_override_config
        from mcp_audit.suppressions import apply_suppressions, validate_ignore_rule

        for rule in ignore_rules:
            validate_ignore_rule(rule)
        ignore_path = override_config
        if ignore_path is None and (config is None or include_discovered):
            ignore_path = Path.home() / ".mcp-audit.yaml"
        try:
            override_applier = OverrideApplier(
                load_override_config(ignore_path) if ignore_path is not None else OverrideConfig()
            )
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise _recovery_error(
                f"cannot load finding overrides ({type(exc).__name__})",
                "finding override file",
                "check the selected override file or use --override-config /dev/null",
                scanned=False,
            ) from None
        stage = "config discovery and parsing"
        sources = review_sources(config, include_discovered, project, clients)
        previous_report = load_previous(previous)
        policy_config = None
        if policy:
            from mcp_audit.policy import load_policy

            try:
                policy_config = load_policy(policy)
            except (OSError, ValueError, yaml.YAMLError) as exc:
                raise _recovery_error(
                    f"cannot load policy ({type(exc).__name__})",
                    "policy file",
                    "check the policy file and rerun mcp-audit check --policy FILE",
                    scanned=False,
                ) from None
        if pin_min_sequence is not None:
            from dataclasses import replace

            from mcp_audit.policy import PolicyConfig

            policy_config = replace(
                policy_config or PolicyConfig(),
                pin_min_sequence=max(pin_min_sequence, policy_config.pin_min_sequence or 0)
                if policy_config
                else pin_min_sequence,
            )
        policy_requires_pins = policy_config is not None and bool(
            policy_config.required_pin_servers
            or policy_config.pin_min_sequence is not None
            or policy_config.fail_on_pin_integrity
            or any(rule.require_pin for rule in policy_config.server_rules.values())
        )
        if pin_file is None and (
            pin_check
            or escalation_check
            or provenance_check
            or integrity_check
            or canary_check
            or verify_artifacts
            or download_artifacts
            or policy_requires_pins
        ):
            from mcp_audit.pinning import DEFAULT_PIN_PATH

            pin_file = DEFAULT_PIN_PATH
        inputs = [Path(path) for path, status in sources.paths if status != "absent"]
        if ignore_path is not None:
            inputs.append(ignore_path)
        if policy is not None:
            inputs.append(policy)
        if pin_file is not None:
            inputs.append(pin_file)
        if previous is not None:
            inputs.append(previous)
        try:
            validate_artifact_paths(
                [("--output-json", output_json), ("--sarif", sarif), ("--html", html), ("--card", card)],
                inputs,
            )
        except click.BadParameter as exc:
            raise _recovery_error(
                strip_controls(exc.format_message()),
                "artifact destination validation",
                "choose verifiable destinations separate from inputs and other artifacts",
                scanned=False,
                exit_code=2,
            ) from None
        servers = sources.servers
        if connect:
            selected = [server for server in servers if server_identity(server) == server_id]
            if len(selected) != 1 or sources.errors:
                raise ValueError(
                    "Selection must match exactly one server with no config diagnostics. Use inspect."
                )
            servers = selected
            out.print(terminal_safe(f"Connecting to {server_id} from {servers[0].config_path}."))
        elif connect_all:
            out.print("Connecting to the reviewed fleet; project servers require --connect-project-configs.")
        if connecting:
            out.print(
                "Configured code may execute and access the network. "
                "Auditor read-only intent is not a sandbox."
            )
        operation = partial(
            run_scan,
            ScanOptions(
                skip_connect=not connecting,
                timeout=timeout,
                max_concurrency=max_concurrency,
                pin_file=pin_file,
                ssrf_check=ssrf_check,
                ssrf_allowlist=ssrf_allowlist,
                egress_check=egress_check,
                egress_allowlist=_merge_host_args(
                    egress_allowlist, policy_config.egress_allowlist if policy_config else []
                ),
                multi_tenant_hosts=_merge_host_args(
                    multi_tenant_hosts, policy_config.multi_tenant_hosts if policy_config else []
                ),
                egress_server_allowlists=(
                    {
                        name: rule.egress_allowlist
                        for name, rule in policy_config.server_rules.items()
                        if rule.egress_allowlist
                    }
                    if policy_config
                    else None
                ),
                pin_check=pin_check,
                escalation_check=escalation_check,
                provenance_check=provenance_check,
                integrity_check=integrity_check,
                verify_artifacts=verify_artifacts,
                download_artifacts=download_artifacts,
                llm_analysis=llm_analysis,
                canary_check=canary_check,
                canary_calls=canary_calls,
                canary_identities=canary_identities,
                canary_safe_tools=canary_safe_tools,
                max_frame_bytes=max_frame_bytes,
                max_surface_bytes=max_surface_bytes,
                sdk_stdio_fallback=sdk_stdio_fallback,
                connect_project_configs=connecting and (connect or connect_project_configs),
                config_only=config is not None and not include_discovered,
                inject_check=inject_check or (card is not None and connecting),
                trifecta_check=trifecta_check or (card is not None and connecting),
                shadow_check=shadow_check or (card is not None and connecting),
            ),
            servers=servers,
            parse_errors=sources.errors,
            override_applier=override_applier,
            _allow_sharding=True,
        )
        stage = "scan"
        report = anyio.run(operation)
        scanned = True
        stage = "report post-processing"
        apply_suppressions(report, cli_rules=ignore_rules, cli_reason=ignore_reason)
        if policy_config is not None:
            from mcp_audit.policy import evaluate_policy

            selected_pin_store = None
            if policy_requires_pins:
                from mcp_audit.pinning import PinStore

                selected_pin_store = PinStore(path=pin_file)
            report.policy_result = evaluate_policy(report, policy_config, pin_store=selected_pin_store)
        safe_report = report.redacted()
        out_report = (
            report._redacted_copy(safe_report.model_dump(mode="json"), identifiers=True)
            if redact
            else safe_report
        )
        payload = json.dumps(out_report.model_dump(mode="json"), indent=2)
        if not json_stdout:
            stage = "terminal rendering"
            ReportGenerator(out).render_terminal(
                report,
                verbose=verbose or details,
                details=details,
                explicit_config=config is not None and not include_discovered,
            )
            if details:
                for warning in safe_report.warnings:
                    out.print(terminal_safe(warning.message))
                _print_sources(out, sources.paths)
        if output_json:
            stage = "--output-json destination"
            output_json.write_text(payload, encoding="utf-8")
            written.append(output_json)
        if sarif:
            stage = "--sarif destination"
            from mcp_audit.sarif import SarifGenerator

            sarif.write_text(
                json.dumps(SarifGenerator().generate(out_report, profile=sarif_profile), indent=2),
                encoding="utf-8",
            )
            written.append(sarif)
        if html:
            stage = "--html destination"
            from mcp_audit.htmlreport import HtmlReportGenerator

            html.write_text(HtmlReportGenerator().generate(out_report, show_host=show_host), encoding="utf-8")
            written.append(html)
        if card is not None:
            stage = "--card destination"
            card.write_text(generate_card(report, names=names, previous=previous_report), encoding="utf-8")
            written.append(card)
            stage = "terminal rendering"
            out.print(terminal_safe(sticker(report)))
        stage = "output summary"
        for path in (output_json, sarif, html, card):
            if path is not None:
                out.print(terminal_safe(f"Wrote {path}"))
        if json_stdout:
            click.echo(payload)
        if report.policy_result is not None and not report.policy_result.passed:
            raise click.exceptions.Exit(2)
    except (OSError, ValueError) as exc:
        raise _recovery_error(
            strip_controls(str(exc)),
            stage,
            "check the named input or output path, then rerun mcp-audit check",
            scanned=scanned,
            written=tuple(written),
        ) from None


@click.command()
@_source_options
@click.option("--card", type=click.Path(path_type=Path), default=Path("checkup.html"), show_default=True)
@click.option(
    "--names", is_flag=True, help="Include redacted server names; no other identifiers or evidence."
)
@click.option(
    "--previous", type=click.Path(path_type=Path), help="Explicit local report JSON for comparison."
)
@click.option("--json", "json_stdout", is_flag=True, help="Emit only AuditReport JSON on stdout.")
@click.option("--output-json", type=click.Path(path_type=Path), help="Write AuditReport JSON to FILE.")
@click.option("--connect", is_flag=True, help="Connect only to the selected server identity, as with check.")
@click.option("--server", "server_id", metavar="CLIENT:SCOPE:NAME")
@click.option("--override-config", type=click.Path(path_type=Path))
@click.pass_context
def checkup(
    ctx: click.Context,
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    clients: tuple[ClientType, ...],
    details: bool,
    card: Path,
    names: bool,
    previous: Path | None,
    connect: bool,
    server_id: str | None,
    override_config: Path | None,
    json_stdout: bool,
    output_json: Path | None,
) -> None:
    """Write a local shareable HTML card; static Preview unless explicitly connected."""
    ctx.invoke(
        check,
        config=config,
        include_discovered=include_discovered,
        project=project,
        clients=clients,
        details=details,
        card=card,
        names=names,
        previous=previous,
        connect=connect,
        server_id=server_id,
        override_config=override_config,
        json_stdout=json_stdout,
        output_json=output_json,
    )


@click.command()
@_source_options
@click.option("--json", "json_stdout", is_flag=True, help="Emit source identities as JSON on stdout.")
@click.option(
    "--output-json", type=click.Path(path_type=Path), help="Write source identities as JSON to FILE."
)
def inspect(
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    clients: tuple[ClientType, ...],
    details: bool,
    json_stdout: bool,
    output_json: Path | None,
) -> None:
    """List server identities, sources and discovery coverage without connecting."""
    try:
        sources = review_sources(config, include_discovered, project, clients)
    except (OSError, ValueError) as exc:
        raise _recovery_error(
            strip_controls(str(exc)),
            "config discovery and parsing",
            "check the selected config path, then rerun mcp-audit inspect",
            scanned=False,
        ) from None
    out = Console(stderr=json_stdout)
    payload = json.dumps(
        {
            "servers": [
                {
                    "identity": server_identity(server),
                    "source": server.source_label,
                    "config_path": server.config_path,
                }
                for server in sources.servers
            ],
            "sources": [{"path": path, "status": status} for path, status in sources.paths],
            "diagnostics": len(sources.errors),
        },
        indent=2,
    )
    if output_json is not None:
        try:
            validate_artifact_paths(
                [("--output-json", output_json)],
                [Path(path) for path, status in sources.paths if status != "absent"],
            )
        except click.BadParameter as exc:
            raise _recovery_error(
                strip_controls(exc.format_message()),
                "--output-json destination",
                "choose a verifiable destination separate from the reviewed config files",
                scanned=True,
                exit_code=2,
            ) from None
        try:
            output_json.write_text(payload, encoding="utf-8")
        except OSError as exc:
            raise _recovery_error(
                f"cannot write JSON output ({type(exc).__name__})",
                "--output-json destination",
                "choose a writable --output-json FILE path and rerun mcp-audit inspect",
                scanned=True,
            ) from None
        out.print(terminal_safe(f"Wrote {output_json}"))
    if json_stdout:
        click.echo(payload)
        return
    if not sources.servers:
        out.print("No MCP servers found. Try mcp-audit demo or mcp-audit check --config ./mcp.json.")
    if sources.errors:
        out.print("PARTIAL: config diagnostics or skipped sources reduce coverage.")
    for server in sources.servers:
        out.print(
            terminal_safe(f"{server_identity(server)} | source: {server.source_label} | {server.config_path}")
        )
        if details:
            out.print(
                terminal_safe(
                    f"Transport: {server.transport.value}; credential keys: "
                    f"{', '.join(server.env_keys + server.headers_keys) or 'none'}"
                )
            )
    _print_sources(out, sources.paths)


@click.command()
@click.pass_context
def demo(ctx: click.Context) -> None:
    """Review the bundled examples/sandbox synthetic fixture, config-only."""
    ctx.invoke(check, config=Path(__file__).parent / "fixtures" / "demo-mcp-config.json")
    click.echo("Demo: bundled examples/sandbox synthetic fixture; config-only, no discovery or connections.")
