"""Claude Code MCP config discoverer (~/.claude.json)."""

import json
import logging
from pathlib import Path
from typing import Any

from mcp_audit.discovery.base import ConfigDiscoverer
from mcp_audit.models import ClientType, ServerConfig, TransportType

logger = logging.getLogger(__name__)


def _parse_server_entry(
    name: str,
    entry: dict[str, Any],
    config_path: str,
    project_path: str | None,
) -> ServerConfig:
    """Convert a single mcpServers entry dict into a ServerConfig."""
    raw_type = entry.get("type", "")

    # Determine transport: explicit "type" field, or infer from presence of url/command
    if raw_type == "http":
        transport = TransportType.HTTP
    elif raw_type == "sse":
        transport = TransportType.SSE
    elif raw_type == "stdio":
        transport = TransportType.STDIO
    elif entry.get("url"):
        transport = TransportType.HTTP
    else:
        transport = TransportType.STDIO

    # Env keys — key names only, never values
    raw_env = entry.get("env") or {}
    env_keys = list(raw_env.keys()) if isinstance(raw_env, dict) else []

    # Header keys for HTTP servers — key names only, never values
    raw_headers = entry.get("headers") or {}
    headers_keys = list(raw_headers.keys()) if isinstance(raw_headers, dict) else []

    args = entry.get("args") or []
    if not isinstance(args, list):
        args = []

    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path=config_path,
        project_path=project_path,
        command=entry.get("command") or None,
        args=[str(a) for a in args],
        env_keys=env_keys,
        transport=transport,
        url=entry.get("url") or None,
        headers_keys=headers_keys,
    )


def _extract_servers(
    mcp_servers: Any,
    config_path: str,
    project_path: str | None,
) -> list[ServerConfig]:
    """Extract ServerConfig list from a mcpServers dict."""
    if not isinstance(mcp_servers, dict):
        return []
    results: list[ServerConfig] = []
    for name, entry in mcp_servers.items():
        if not isinstance(entry, dict):
            continue
        try:
            results.append(_parse_server_entry(name, entry, config_path, project_path))
        except Exception:
            logger.debug("Failed to parse server %r in %s", name, config_path)
    return results


class ClaudeCodeDiscoverer(ConfigDiscoverer):
    """Discovers MCP servers from Claude Code's ~/.claude.json config."""

    def config_paths(self) -> list[Path]:
        return [Path.home() / ".claude.json"]

    def parse(self, path: Path) -> list[ServerConfig]:
        config_path = str(path)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            logger.debug("Could not read %s", config_path)
            return []

        if not isinstance(data, dict):
            return []

        results: list[ServerConfig] = []

        # Global mcpServers (top-level)
        global_servers = data.get("mcpServers")
        results.extend(_extract_servers(global_servers, config_path, None))

        # Per-project mcpServers
        projects = data.get("projects") or {}
        if isinstance(projects, dict):
            for project_path, project_data in projects.items():
                if not isinstance(project_data, dict):
                    continue
                project_servers = project_data.get("mcpServers")
                results.extend(_extract_servers(project_servers, config_path, str(project_path)))

        logger.debug("Claude Code: found %d servers in %s", len(results), config_path)
        return results
