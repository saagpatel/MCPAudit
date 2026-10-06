"""Claude Code MCP config discoverer (~/.claude.json)."""

import logging
from pathlib import Path

from mcp_audit.discovery._config import read_config
from mcp_audit.discovery._entry import parse_server_map
from mcp_audit.discovery.base import ConfigDiscoverer, ConfigParseError
from mcp_audit.models import ClientType, ServerConfig
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())


def parse_mapping(
    data: object,
    config_path: str,
    parse_errors: list[ConfigParseError] | None = None,
    *,
    sniff_format: bool = False,
) -> list[ServerConfig]:
    """Extract global and project maps; explicit configs also accept VS Code layouts."""
    if not isinstance(data, dict):
        return []
    results: list[ServerConfig] = []
    found = False
    client = ClientType.CLAUDE_CODE
    for key in ("mcpServers", "servers") if sniff_format else ("mcpServers",):
        if key in data:
            found = True
            results.extend(parse_server_map(data[key], config_path, client, parse_errors))
    if sniff_format and "mcp" in data:
        section = data["mcp"]
        if not isinstance(section, dict):
            raise ConfigParseError(config_path, client, "mcp section is not an object")
        if "servers" in section:
            found = True
            results.extend(parse_server_map(section["servers"], config_path, client, parse_errors))
    if "projects" in data:
        projects = data["projects"]
        if not isinstance(projects, dict):
            raise ConfigParseError(config_path, client, "projects map is not an object")
        for project_path, project_data in projects.items():
            if not isinstance(project_data, dict):
                raise ConfigParseError(config_path, client, "project entry is not an object")
            if "mcpServers" in project_data:
                found = True
                results.extend(
                    parse_server_map(
                        project_data["mcpServers"], config_path, client, parse_errors, str(project_path)
                    )
                )
    if sniff_format and not found:
        raise ConfigParseError(
            config_path, client, f"no server map found in {config_path} (unsupported client config format)"
        )
    return results


class ClaudeCodeDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Claude Code's ~/.claude.json config."""

    def config_paths(self) -> list[Path]:
        # ~/.claude.json holds global + per-project servers; a repo-root
        # .mcp.json is Claude Code's project-shared config (top-level
        # mcpServers), discovered relative to the current working directory so
        # repo-local configs are audited in CI and pre-commit runs.
        return [Path.home() / ".claude.json", Path.cwd() / ".mcp.json"]

    def parse(self, path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
        data = read_config(path, ClientType.CLAUDE_CODE, parse_errors)
        return parse_mapping(data, str(path), parse_errors)
