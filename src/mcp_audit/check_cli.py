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
        self.exit_code = exit_code


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


def _print_sources(out: Console, paths: list[tuple[str, str]]) -> None:
    for path, status in paths:
        out.print(terminal_safe(f"{status}: {path}"))
    out.print("Unsupported source: Codex (no adapter). No recursive search or config includes.")
    out.print("Project and workstation entries are listed separately; no client precedence is inferred.")


@click.command()
@_source_options
@click.option("--connect", is_flag=True, help="Connect only to the explicitly selected server identity.")
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
    "--override-config", type=click.Path(path_type=Path), help="Ignore YAML (default: ~/.mcp-audit.yaml)."
)
@click.option(
    "--ignore", "ignore_rules", multiple=True, metavar="MCP0xx", help="Ignore a finding rule for this run."
)
@click.option("--ignore-reason", help="Reason for one-run ignores (required for HIGH findings).")
@click.option("--color", type=click.Choice(["auto", "always", "never"]), default="auto", show_default=True)
def check(
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    clients: tuple[ClientType, ...],
    details: bool,
    connect: bool,
    server_id: str | None,
    json_stdout: bool,
    output_json: Path | None,
    sarif: Path | None,
    html: Path | None,
    show_host: bool,
    policy: Path | None,
    color: str,
    override_config: Path | None,
    ignore_rules: tuple[str, ...],
    ignore_reason: str | None,
    card: Path | None,
    names: bool,
    previous: Path | None,
) -> None:
    """Review configs statically; runtime security is not checked by default."""
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
        from mcp_audit.overrides import load_override_config
        from mcp_audit.suppressions import apply_suppressions, validate_ignore_rule

        for rule in ignore_rules:
            validate_ignore_rule(rule)
        ignore_path = override_config
        if ignore_path is None and (config is None or include_discovered):
            ignore_path = Path.home() / ".mcp-audit.yaml"
        try:
            ignores = load_override_config(ignore_path).ignore if ignore_path is not None else []
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
        inputs = [Path(path) for path, status in sources.paths if status != "absent"]
        if ignore_path is not None:
            inputs.append(ignore_path)
        if policy is not None:
            inputs.append(policy)
        if previous is not None:
            inputs.append(previous)
        validate_artifact_paths(
            [("--output-json", output_json), ("--sarif", sarif), ("--html", html), ("--card", card)], inputs
        )
        servers = sources.servers
        if connect:
            selected = [server for server in servers if server_identity(server) == server_id]
            if len(selected) != 1 or sources.errors:
                raise ValueError(
                    "Selection must match exactly one server with no config diagnostics. Use inspect."
                )
            servers = selected
            out.print(terminal_safe(f"Connecting to {server_id} from {servers[0].config_path}."))
            out.print(
                "Configured code may execute and access the network. "
                "Auditor read-only intent is not a sandbox."
            )
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
        operation = partial(
            run_scan,
            ScanOptions(
                skip_connect=not connect,
                connect_project_configs=connect,
                config_only=config is not None and not include_discovered,
                inject_check=card is not None and connect,
                trifecta_check=card is not None and connect,
                shadow_check=card is not None and connect,
            ),
            servers=servers,
            parse_errors=sources.errors,
        )
        stage = "scan"
        report = anyio.run(operation)
        scanned = True
        apply_suppressions(report, ignores, cli_rules=ignore_rules, cli_reason=ignore_reason)
        if policy_config is not None:
            from mcp_audit.policy import evaluate_policy

            report.policy_result = evaluate_policy(report, policy_config)
        safe_report = report.redacted()
        payload = json.dumps(safe_report.model_dump(mode="json"), indent=2)
        if not json_stdout:
            ReportGenerator(out).render_terminal(
                report,
                verbose=details,
                details=details,
                explicit_config=config is not None and not include_discovered,
            )
            if details:
                for warning in safe_report.warnings:
                    out.print(terminal_safe(warning.message))
                _print_sources(out, sources.paths)
        if output_json:
            output_json.write_text(payload, encoding="utf-8")
            written.append(output_json)
        if sarif:
            from mcp_audit.sarif import SarifGenerator

            sarif.write_text(json.dumps(SarifGenerator().generate(safe_report), indent=2), encoding="utf-8")
            written.append(sarif)
        if html:
            from mcp_audit.htmlreport import HtmlReportGenerator

            html.write_text(
                HtmlReportGenerator().generate(safe_report, show_host=show_host), encoding="utf-8"
            )
            written.append(html)
        if card is not None:
            card.write_text(generate_card(report, names=names, previous=previous_report), encoding="utf-8")
            written.append(card)
            out.print(terminal_safe(sticker(report)))
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
        except (OSError, ValueError) as exc:
            raise _recovery_error(
                strip_controls(str(exc)),
                "--output-json destination",
                "choose a destination separate from the reviewed config files",
                scanned=True,
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
