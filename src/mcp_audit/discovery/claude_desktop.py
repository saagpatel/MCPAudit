"""Claude Desktop MCP config discoverer."""

import logging
import platform
from pathlib import Path

from mcp_audit.discovery._config import read_config
from mcp_audit.discovery._entry import parse_server_map
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

    def parse(self, path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
        data = read_config(path, ClientType.CLAUDE_DESKTOP, parse_errors, jsonc=False)
        if "mcpServers" not in data:
            return []
        return parse_server_map(data["mcpServers"], str(path), ClientType.CLAUDE_DESKTOP, parse_errors)
