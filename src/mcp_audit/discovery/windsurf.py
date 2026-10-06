"""Windsurf MCP config discoverer (~/.codeium/windsurf/mcp_config.json)."""

import json
import logging
from pathlib import Path
from typing import Any

from mcp_audit.discovery._entry import parse_server_entry
from mcp_audit.discovery.base import ConfigDiscoverer, ConfigParseError
from mcp_audit.models import ClientType, ServerConfig
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())


class WindsurfDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Windsurf's config file."""

    def config_paths(self) -> list[Path]:
        return [Path.home() / ".codeium" / "windsurf" / "mcp_config.json"]

    def parse(self, path: Path) -> list[ServerConfig]:
        config_path = str(path)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ConfigParseError(config_path, ClientType.WINDSURF, f"{type(exc).__name__}: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigParseError(config_path, ClientType.WINDSURF, "top-level structure is not an object")

        mcp_servers = data.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            logger.debug("Windsurf: no mcpServers in %s", config_path)
            return []

        results: list[ServerConfig] = []
        for name, entry in mcp_servers.items():
            if not isinstance(entry, dict):
                continue
            try:
                results.append(parse_server_entry(name, entry, config_path, ClientType.WINDSURF))
            except Exception:
                logger.debug("Failed to parse server %r in %s", name, config_path)

        logger.debug("Windsurf: found %d servers in %s", len(results), config_path)
        return results
