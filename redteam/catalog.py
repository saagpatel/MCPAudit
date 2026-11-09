"""Shared declared catalog snapshots; never verified current server surfaces."""

from pathlib import Path

from mcp_audit.models import ServerConfig
from redteam.surface import ServerSurface

CATALOG = Path(__file__).parent / "fixtures/servers/catalog"
CATALOG_FILES = {
    "npm:@modelcontextprotocol/server-filesystem": "npm-modelcontextprotocol-server-filesystem.json",
    "pypi:mcp-server-git": "pypi-mcp-server-git.json",
    "npm:@playwright/mcp@0.0.76": "npm-playwright-mcp-0.0.76.json",
    "local:machine-room": "local-machine-room.json",
}
UNAVAILABLE_CATALOG = {
    "npm:xcodebuildmcp@2.6.2": (
        "No version-matched tool documentation at getsentry/XcodeBuildMCP tag v2.6.2; "
        "the tagged README links only the unversioned https://xcodebuildmcp.com/docs/tools"
    ),
}


def load_catalog() -> dict[str, ServerSurface]:
    catalog: dict[str, ServerSurface] = {}
    for key, name in sorted(CATALOG_FILES.items()):
        try:
            catalog[key] = ServerSurface.load(CATALOG / name)
        except FileNotFoundError:
            continue
    return catalog


def catalog_surface(
    config: ServerConfig, catalog: dict[str, ServerSurface]
) -> tuple[ServerSurface | None, str | None]:
    """Match launch package identity, including the exact version when curated."""
    command = Path(config.command or "").name
    identity: str | None = None
    if command == "machine-room" and "mcp" in config.args:
        identity = "local:machine-room"
    elif command == "uvx" and config.args and config.args[0] == "mcp-server-git":
        identity = "pypi:mcp-server-git"
    elif command == "npx":
        args = list(config.args)
        if args and args[0] in {"-y", "--yes"}:
            args.pop(0)
        if args and not args[0].startswith("-"):
            identity = f"npm:{args[0]}"
    if identity in catalog:
        return catalog[identity], None
    if identity in UNAVAILABLE_CATALOG:
        return None, UNAVAILABLE_CATALOG[identity]
    if identity is not None:
        for package in ("npm:@playwright/mcp", "npm:xcodebuildmcp"):
            if identity == package or identity.startswith(package + "@"):
                versions = sorted(
                    key.removeprefix(package + "@") for key in catalog if key.startswith(package + "@")
                )
                if versions:
                    configured = (
                        identity.removeprefix(package + "@") if identity != package else "unversioned"
                    )
                    return None, f"catalog has {', '.join(versions)}, configured {configured}"
    return None, None
