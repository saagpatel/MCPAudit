"""VS Code MCP config discoverer.

Checks (in order):
1. .vscode/mcp.json in the current working directory
2. ~/.vscode/mcp.json (user-level standalone file)
3. ~/Library/Application Support/Code/User/settings.json (macOS, mcp.servers key)
4. ~/.config/Code/User/settings.json (Linux, mcp.servers key)
"""

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


def _settings_paths() -> list[Path]:
    system = platform.system()
    if system == "Darwin":
        return [Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json"]
    return [Path.home() / ".config" / "Code" / "User" / "settings.json"]


class VSCodeDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from VS Code config files."""

    def config_paths(self) -> list[Path]:
        paths = [
            Path.cwd() / ".vscode" / "mcp.json",
            Path.home() / ".vscode" / "mcp.json",
        ]
        paths.extend(_settings_paths())
        return paths

    def parse(self, path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
        data = read_config(path, ClientType.VSCODE, parse_errors, jsonc=True)
        results: list[ServerConfig] = []
        for key in ("mcpServers", "servers"):
            if key in data:
                results.extend(
                    parse_server_map(
                        data[key], str(path), ClientType.VSCODE, parse_errors, map_pointer=f"/{key}"
                    )
                )
        if "mcp" in data:
            section = data["mcp"]
            if not isinstance(section, dict):
                raise ConfigParseError(str(path), ClientType.VSCODE, "mcp section is not an object")
            if "servers" in section:
                results.extend(
                    parse_server_map(
                        section["servers"],
                        str(path),
                        ClientType.VSCODE,
                        parse_errors,
                        map_pointer="/mcp/servers",
                    )
                )
        return results
