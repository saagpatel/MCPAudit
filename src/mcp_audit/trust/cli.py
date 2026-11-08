"""`mcp-audit trust TARGET`: check an MCP server before you install it."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import click
from pydantic import ValidationError

from mcp_audit.trust.models import TrustPin
from mcp_audit.trust.render import html, terminal
from mcp_audit.trust.resolve import DEFAULT_REGISTRY_URL, Resolver, TargetError, default_fetcher, parse_target
from mcp_audit.trust.run import TrustOptions, run_trust
from mcp_audit.trust.sandbox import (
    DEFAULT_NODE_IMAGE,
    DEFAULT_PYTHON_IMAGE,
    DEFAULT_SINK_BASE_IMAGE,
    RuntimeUnavailable,
    SandboxConfig,
)
from mcp_audit.trust.session import ExercisePlan
from mcp_audit.trust.verdict import server_key

EXIT_CODES = {"no_mismatches_observed": 0, "review": 1, "do_not_install": 1, "incomplete": 3}


@click.command("trust")
@click.argument("target")
@click.option(
    "--out",
    "out_dir",
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory for card.json, card.html and pin.json [default: ./mcp-audit-trust/<server>].",
)
@click.option("--json", "as_json", is_flag=True, help="Print the card as JSON instead of text.")
@click.option(
    "--pin",
    "pin_path",
    type=click.Path(dir_okay=False, exists=True, path_type=Path),
    help="Earlier pin.json to compare the tool surface against (drift).",
)
@click.option("--safe-tool", "safe_tools", multiple=True, help="Also exercise this tool. Repeatable.")
@click.option("--max-calls", default=10, show_default=True, type=click.IntRange(0, 50))
@click.option("--call-timeout", default=20.0, show_default=True, type=click.FloatRange(1, 300))
@click.option(
    "--allow-install-scripts",
    is_flag=True,
    help="Run npm install scripts and allow PyPI source builds during install.",
)
@click.option("--runtime", default="docker", show_default=True, help="Docker-compatible container CLI.")
@click.option("--registry-url", default=DEFAULT_REGISTRY_URL, show_default=True)
@click.option("--node-image", default=DEFAULT_NODE_IMAGE, show_default=True)
@click.option("--python-image", default=DEFAULT_PYTHON_IMAGE, show_default=True)
@click.option("--sink-image", default=DEFAULT_SINK_BASE_IMAGE, show_default=True)
def trust(
    target: str,
    out_dir: Path | None,
    as_json: bool,
    pin_path: Path | None,
    safe_tools: tuple[str, ...],
    max_calls: int,
    call_timeout: float,
    allow_install_scripts: bool,
    runtime: str,
    registry_url: str,
    node_image: str,
    python_image: str,
    sink_image: str,
) -> None:
    """Check an MCP server before installing it (experimental).

    Experimental: output, rules and flags may change. Known limits: file reads
    are not recorded; only tools declared read-only are called, with synthetic
    inputs; one short session is observed; remote servers are only listed
    from outside, so their own writes and egress are unseen. A clean card is
    evidence, not a guarantee. See docs/guides/trust-before-connect.md.

    TARGET is an MCP Registry name (io.github.owner/name), npm:PACKAGE[@VERSION],
    pypi:PACKAGE[==VERSION], or an https:// remote URL. Packages are installed
    and run in a throwaway container with no host mounts, no credentials and
    no real network; remote servers are only listed from outside. Writes a
    verdict card (terminal, JSON, HTML) and a pin of tool names and
    descriptions for later drift checks.

    Exit codes: 0 no mismatches observed, 1 review or do not install,
    3 incomplete or no container runtime.
    """
    try:
        parse_target(target)
    except TargetError as exc:
        raise click.BadParameter(str(exc), param_hint="TARGET") from None
    previous = None
    if pin_path is not None:
        try:
            previous = TrustPin.model_validate_json(pin_path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise click.BadParameter(f"Not a trust pin ({type(exc).__name__}).", param_hint="--pin") from None
    options = TrustOptions(
        sandbox=SandboxConfig(
            binary=runtime,
            node_image=node_image,
            python_image=python_image,
            sink_base_image=sink_image,
            allow_install_scripts=allow_install_scripts,
        ),
        plan=ExercisePlan(max_calls=max_calls, call_timeout=call_timeout, safe_tools=frozenset(safe_tools)),
        previous_pin=previous,
    )
    resolver = Resolver(default_fetcher(registry_url), registry_url)
    try:
        result = anyio.run(run_trust, target, resolver, options)
    except RuntimeUnavailable as exc:
        click.echo(f"Error: {exc}", err=True)
        click.echo("Nothing was installed or started. Start a container runtime and rerun.", err=True)
        raise SystemExit(3) from None
    card = result.card
    directory = out_dir or Path("mcp-audit-trust") / server_key(card.target)
    directory.mkdir(parents=True, exist_ok=True)
    payload = card.model_dump_json(by_alias=True, indent=2)
    (directory / "card.json").write_text(payload + "\n", encoding="utf-8")
    (directory / "card.html").write_text(html(card), encoding="utf-8")
    written = [directory / "card.json", directory / "card.html"]
    if result.pin is not None:
        pin_file = directory / "pin.json"
        if pin_path is not None and pin_file.resolve() == pin_path.resolve():
            # Never move the baseline: a drifted surface must not become the next anchor.
            pin_file = directory / "pin.new.json"
        pin_file.write_text(result.pin.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
        written.append(pin_file)
    if as_json:
        click.echo(json.dumps(json.loads(payload), indent=2))
    else:
        click.echo(terminal(card))
        click.echo("")
        click.echo("Written: " + ", ".join(str(path) for path in written))
    raise SystemExit(EXIT_CODES[card.verdict])
