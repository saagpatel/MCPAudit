"""Claude Desktop MCP config discoverer."""

import json
import logging
import platform
from pathlib import Path
from typing import Any

from mcp_audit.discovery._entry import parse_server_entry
from mcp_audit.discovery.base import ConfigDiscoverer, ConfigParseError
from mcp_audit.models import ClientType, ServerConfig
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())


def _config_paths_for_platform() -> list[Path]:
    system = platform.system()
    if system == "Darwin":
        return [Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"]
    # Linux
    return [Path.home() / ".config" / "Claude" / "claude_desktop_config.json"]


class ClaudeDesktopDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Claude Desktop's config file."""

    def config_paths(self) -> list[Path]:
        return _config_paths_for_platform()

    def parse(self, path: Path) -> list[ServerConfig]:
        config_path = str(path)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ConfigParseError(
                config_path, ClientType.CLAUDE_DESKTOP, f"{type(exc).__name__}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ConfigParseError(
                config_path, ClientType.CLAUDE_DESKTOP, "top-level structure is not an object"
            )

        mcp_servers = data.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            logger.debug("Claude Desktop: no mcpServers in %s", config_path)
            return []

        results: list[ServerConfig] = []
        for name, entry in mcp_servers.items():
            if not isinstance(entry, dict):
                continue
            try:
                results.append(parse_server_entry(name, entry, config_path, ClientType.CLAUDE_DESKTOP))
            except Exception:
                logger.debug("Failed to parse server %r in %s", name, config_path)

        logger.debug("Claude Desktop: found %d servers in %s", len(results), config_path)
        return results
