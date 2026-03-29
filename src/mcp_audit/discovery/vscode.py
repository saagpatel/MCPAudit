"""VS Code MCP config discoverer.

Checks (in order):
1. .vscode/mcp.json in the current working directory
2. ~/.vscode/mcp.json (user-level standalone file)
3. ~/Library/Application Support/Code/User/settings.json (macOS, mcp.servers key)
4. ~/.config/Code/User/settings.json (Linux, mcp.servers key)
"""

import json
import logging
import platform
from pathlib import Path
from typing import Any

from mcp_audit.discovery.base import ConfigDiscoverer
from mcp_audit.models import ClientType, ServerConfig, TransportType

logger = logging.getLogger(__name__)


def _settings_paths() -> list[Path]:
    system = platform.system()
    if system == "Darwin":
        return [Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json"]
    return [Path.home() / ".config" / "Code" / "User" / "settings.json"]


def _parse_mcp_servers_dict(
    mcp_servers: Any,
    config_path: str,
) -> list[ServerConfig]:
    """Parse a standard mcpServers dict into ServerConfig list."""
    if not isinstance(mcp_servers, dict):
        return []
    results: list[ServerConfig] = []
    for name, entry in mcp_servers.items():
        if not isinstance(entry, dict):
            continue
        try:
            raw_env = entry.get("env") or {}
            env_keys = list(raw_env.keys()) if isinstance(raw_env, dict) else []
            args = entry.get("args") or []
            if not isinstance(args, list):
                args = []

            # VS Code may use "url" for HTTP transport
            raw_type = entry.get("type", "")
            if raw_type == "http" or entry.get("url"):
                transport = TransportType.HTTP
                raw_headers = entry.get("headers") or {}
                headers_keys = list(raw_headers.keys()) if isinstance(raw_headers, dict) else []
            else:
                transport = TransportType.STDIO
                headers_keys = []

            results.append(
                ServerConfig(
                    name=name,
                    client=ClientType.VSCODE,
                    config_path=config_path,
                    project_path=None,
                    command=entry.get("command") or None,
                    args=[str(a) for a in args],
                    env_keys=env_keys,
                    transport=transport,
                    url=entry.get("url") or None,
                    headers_keys=headers_keys,
                )
            )
        except Exception:
            logger.debug("Failed to parse server %r in %s", name, config_path)
    return results


class VSCodeDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from VS Code config files."""

    def config_paths(self) -> list[Path]:
        paths = [
            Path.cwd() / ".vscode" / "mcp.json",
            Path.home() / ".vscode" / "mcp.json",
        ]
        paths.extend(_settings_paths())
        return paths

    def parse(self, path: Path) -> list[ServerConfig]:
        config_path = str(path)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            logger.debug("Could not read %s", config_path)
            return []

        if not isinstance(data, dict):
            return []

        # Standalone mcp.json: top-level mcpServers key
        if "mcpServers" in data:
            results = _parse_mcp_servers_dict(data["mcpServers"], config_path)
            logger.debug("VS Code: found %d servers in %s", len(results), config_path)
            return results

        # settings.json: mcp.servers key (VS Code's embedded MCP config)
        mcp_section = data.get("mcp") or {}
        if isinstance(mcp_section, dict) and "servers" in mcp_section:
            results = _parse_mcp_servers_dict(mcp_section["servers"], config_path)
            logger.debug("VS Code: found %d servers in settings %s", len(results), config_path)
            return results

        logger.debug("VS Code: no MCP servers found in %s", config_path)
        return []
