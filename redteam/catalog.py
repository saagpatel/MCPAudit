"""Shared, unversioned catalog snapshots; not verified current server surfaces."""

from pathlib import Path

from redteam.surface import ServerSurface

CATALOG = Path(__file__).parent / "fixtures/servers/catalog"
CATALOG_FILES = {
    "npm:@modelcontextprotocol/server-filesystem": "npm-modelcontextprotocol-server-filesystem.json",
    "pypi:mcp-server-git": "pypi-mcp-server-git.json",
}


def load_catalog() -> dict[str, ServerSurface]:
    return {key: ServerSurface.load(CATALOG / name) for key, name in sorted(CATALOG_FILES.items())}
