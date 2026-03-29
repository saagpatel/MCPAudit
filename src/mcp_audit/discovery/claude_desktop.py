"""Claude Desktop MCP config discoverer."""

import json
import logging
import platform
from pathlib import Path
from typing import Any

from mcp_audit.discovery.base import ConfigDiscoverer
from mcp_audit.models import ClientType, ServerConfig, TransportType

logger = logging.getLogger(__name__)


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
        except Exception:
            logger.debug("Could not read %s", config_path)
            return []

        if not isinstance(data, dict):
            return []

        mcp_servers = data.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            logger.debug("Claude Desktop: no mcpServers in %s", config_path)
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
                results.append(
                    ServerConfig(
                        name=name,
                        client=ClientType.CLAUDE_DESKTOP,
                        config_path=config_path,
                        project_path=None,
                        command=entry.get("command") or None,
                        args=[str(a) for a in args],
                        env_keys=env_keys,
                        transport=TransportType.STDIO,
                    )
                )
            except Exception:
                logger.debug("Failed to parse server %r in %s", name, config_path)

        logger.debug("Claude Desktop: found %d servers in %s", len(results), config_path)
        return results
