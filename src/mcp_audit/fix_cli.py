"""Offline, argument-only suggestions for two conservative config fixes."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import click

from mcp_audit.models import TransportType
from mcp_audit.pkgverify import PackageRef, _split_npm_spec
from mcp_audit.redaction import _redact_config_pointer
from mcp_audit.review_discovery import review_sources, server_identity

_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_NUMBER = r"(?:0|[1-9][0-9]*)"
_PRERELEASE = rf"(?:{_NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_VERSION = re.compile(
    rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}"
    rf"(?:-{_PRERELEASE}(?:\.{_PRERELEASE})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_FILESYSTEM = "@modelcontextprotocol/server-filesystem"


def _narrow_path(value: str, roots: list[str]) -> str:
    """Accept a strict subdirectory; `$HOME/...` is checked symbolically, so it works on any host."""
    symbolic = value.startswith("$HOME/")
    rest = value[len("$HOME/") :] if symbolic else value
    parts = rest.split("/")
    candidate = PurePosixPath(value)
    home = PurePosixPath(Path.home().as_posix())
    if (
        "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(part in {".", ".."} for part in parts)
        or (symbolic and (not rest or rest.startswith("/")))
        or (
            not symbolic
            and (not candidate.is_absolute() or value.startswith("//") or candidate == PurePosixPath("/"))
        )
        or (not symbolic and (candidate == home or ("$HOME" in roots and not candidate.is_relative_to(home))))
    ):
        raise click.BadParameter(
            "supply a strict subdirectory of the configured root; use an absolute path or $HOME/subdir",
            param_hint="--path",
        )
    return value


@click.command()
@click.argument("server")
@click.option(
    "--config", required=True, type=click.Path(path_type=Path), help="Read only this explicit config file."
)
@click.option("--package-version", metavar="VERSION", help="Exact npm version you supply; never fetched.")
@click.option("--path", "narrower_path", metavar="DIRECTORY", help="Narrower filesystem root you supply.")
def fix(server: str, config: Path, package_version: str | None, narrower_path: str | None) -> None:
    """Preview fixes for SERVER (unique name or exact identity); never write configs."""
    if package_version is not None and _VERSION.fullmatch(package_version) is None:
        raise click.BadParameter("supply an exact version such as 1.2.3", param_hint="--package-version")
    try:
        sources = review_sources(config=config)
    except (OSError, ValueError) as exc:
        raise click.ClickException(
            f"Cannot read the selected config ({type(exc).__name__}); check --config. Nothing written."
        ) from None
    if sources.errors:
        raise click.ClickException(
            "Config has diagnostics; repair it before requesting fixes. Nothing written."
        )
    selected = [
        entry for entry in sources.servers if entry.name == server or server_identity(entry) == server
    ]
    if len(selected) != 1:
        raise click.ClickException(
            "Select exactly one server by unique name or CLIENT:SCOPE:NAME. "
            "Use inspect --config FILE. Nothing written."
        )
    entry = selected[0]
    if entry.config_pointer is None:
        raise click.ClickException("Cannot locate this server inside the config file. Nothing written.")
    if _redact_config_pointer(entry.config_pointer) != entry.config_pointer:
        raise click.ClickException(
            "The server's config location contains credential-shaped text; previews are withheld. "
            "Nothing written."
        )
    args = entry.args
    patches: list[dict[str, str]] = []
    npx_form = (
        entry.transport == TransportType.STDIO
        and not entry.url
        and Path(entry.command or "").name == "npx"
        and len(args) >= 2
        and args[0] == "-y"
    )
    # The strict `npx -y PKG` form names the package directly; generic runner
    # resolution would skip npx subcommand words that are also package names.
    refs = [PackageRef("npm", *_split_npm_spec(args[1]))] if npx_form else []
    simple_npx = (
        npx_form
        and _PACKAGE.fullmatch(refs[0].name) is not None
        and args[1] == refs[0].name + (f"@{refs[0].version}" if refs[0].version else "")
    )
    pin_supported = simple_npx and refs[0].version is None
    filesystem_supported = (
        simple_npx
        and refs[0].name == _FILESYSTEM
        and (refs[0].version is None or _VERSION.fullmatch(refs[0].version) is not None)
        and len(args) > 2
        and all(arg.startswith("/") or arg == "$HOME" or arg.startswith("$HOME/") for arg in args[2:])
    )
    roots = [arg for arg in args[2:] if arg in {"/", "$HOME"}] if filesystem_supported else []
    if package_version is not None and not pin_supported:
        raise click.ClickException("No supported unpinned npx -y package to fix. Nothing written.")
    if narrower_path is not None and not roots:
        raise click.ClickException("No supported filesystem root of $HOME or / to fix. Nothing written.")
    if pin_supported:
        patches.append(
            {
                "op": "replace",
                "path": f"{entry.config_pointer}/args/1",
                "value": f"{refs[0].name}@{package_version or '<version you supply>'}",
            }
        )
    if roots:
        replacement = (
            _narrow_path(narrower_path, roots) if narrower_path is not None else "<narrower path you supply>"
        )
        for index, arg in enumerate(args[2:], start=2):
            if arg in {"/", "$HOME"}:
                patches.append(
                    {"op": "replace", "path": f"{entry.config_pointer}/args/{index}", "value": replacement}
                )
    click.echo("Dry-run suggestions — not written to disk.")
    if not patches:
        click.echo("No supported fix: only unpinned npx -y packages and filesystem roots of $HOME or /.")
        return
    click.echo("Argument replacements only; preserve all other config fields. Replace any placeholders.")
    click.echo(json.dumps(patches, indent=2, ensure_ascii=True))
    click.echo(
        "Review before applying manually. Package availability and runtime access are not verified; "
        "path narrowing is lexical only (symlinks are not checked)."
    )
