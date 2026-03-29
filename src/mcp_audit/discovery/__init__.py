"""Config discovery — aggregates MCP server configs from all supported clients."""

import logging

from mcp_audit.discovery.base import ConfigDiscoverer
from mcp_audit.discovery.claude_code import ClaudeCodeDiscoverer
from mcp_audit.discovery.claude_desktop import ClaudeDesktopDiscoverer
from mcp_audit.discovery.cursor import CursorDiscoverer
from mcp_audit.discovery.vscode import VSCodeDiscoverer
from mcp_audit.discovery.windsurf import WindsurfDiscoverer
from mcp_audit.models import ClientType, ServerConfig

logger = logging.getLogger(__name__)

_DISCOVERERS: dict[ClientType, type[ConfigDiscoverer]] = {
    ClientType.CLAUDE_CODE: ClaudeCodeDiscoverer,
    ClientType.CLAUDE_DESKTOP: ClaudeDesktopDiscoverer,
    ClientType.CURSOR: CursorDiscoverer,
    ClientType.VSCODE: VSCodeDiscoverer,
    ClientType.WINDSURF: WindsurfDiscoverer,
}


def discover_all_configs(
    clients: list[ClientType] | None = None,
) -> list[ServerConfig]:
    """Discover MCP server configs from all (or filtered) clients.

    Deduplicates by (name, client, config_path, project_path).
    """
    active = clients if clients is not None else list(_DISCOVERERS.keys())
    seen: set[tuple[str, str, str, str | None]] = set()
    results: list[ServerConfig] = []

    for client_type in active:
        discoverer_cls = _DISCOVERERS.get(client_type)
        if discoverer_cls is None:
            logger.debug("No discoverer registered for %s", client_type)
            continue
        discoverer = discoverer_cls()
        for server in discoverer.discover():
            key = (server.name, server.client.value, server.config_path, server.project_path)
            if key in seen:
                logger.debug("Skipping duplicate server %r from %s", server.name, server.config_path)
                continue
            seen.add(key)
            results.append(server)

    logger.debug("Discovery complete: %d unique servers found", len(results))
    return results


__all__ = [
    "ConfigDiscoverer",
    "ClaudeCodeDiscoverer",
    "ClaudeDesktopDiscoverer",
    "CursorDiscoverer",
    "VSCodeDiscoverer",
    "WindsurfDiscoverer",
    "discover_all_configs",
]
