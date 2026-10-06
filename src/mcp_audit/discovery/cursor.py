"""Cursor MCP config discoverer (~/.cursor/mcp.json, JSONC format)."""

import logging
from pathlib import Path

from mcp_audit.discovery._config import read_config
from mcp_audit.discovery._entry import parse_server_map
from mcp_audit.discovery.base import ConfigDiscoverer, ConfigParseError
from mcp_audit.models import ClientType, ServerConfig
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())


class CursorDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Cursor's ~/.cursor/mcp.json (JSONC) config."""

    def config_paths(self) -> list[Path]:
        return [Path.home() / ".cursor" / "mcp.json"]

    def parse(self, path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
        data = read_config(path, ClientType.CURSOR, parse_errors, jsonc=True)
        if "mcpServers" not in data:
            return []
        return parse_server_map(data["mcpServers"], str(path), ClientType.CURSOR, parse_errors)
