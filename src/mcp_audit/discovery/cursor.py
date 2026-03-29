"""Cursor MCP config discoverer (~/.cursor/mcp.json, JSONC format)."""

import logging
from pathlib import Path
from typing import Any

import json5

from mcp_audit.discovery.base import ConfigDiscoverer
from mcp_audit.models import ClientType, ServerConfig, TransportType

logger = logging.getLogger(__name__)


class CursorDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Cursor's ~/.cursor/mcp.json (JSONC) config."""

    def config_paths(self) -> list[Path]:
        return [Path.home() / ".cursor" / "mcp.json"]

    def parse(self, path: Path) -> list[ServerConfig]:
        config_path = str(path)
        try:
            data: Any = json5.loads(path.read_text(encoding="utf-8"))
        except Exception:
            logger.debug("Could not read/parse %s", config_path)
            return []

        if not isinstance(data, dict):
            return []

        mcp_servers = data.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            logger.debug("Cursor: no mcpServers in %s", config_path)
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
                        client=ClientType.CURSOR,
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

        logger.debug("Cursor: found %d servers in %s", len(results), config_path)
        return results
