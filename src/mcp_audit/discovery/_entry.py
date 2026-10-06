"""Shared parsing for individual MCP server config entries."""

from typing import Any, Literal

from mcp_audit.models import ClientType, ServerConfig, TransportType


def parse_server_entry(
    name: str,
    entry: dict[str, Any],
    config_path: str,
    client: ClientType,
    project_path: str | None = None,
    *,
    scope: Literal["workstation", "project"] = "workstation",
) -> ServerConfig:
    """Convert one client config entry into a common ServerConfig."""
    raw_type = entry.get("type", "")
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

    raw_env = entry.get("env") or {}
    env_keys = list(raw_env.keys()) if isinstance(raw_env, dict) else []
    raw_headers = entry.get("headers") or {}
    headers_keys = (
        list(raw_headers.keys())
        if isinstance(raw_headers, dict)
        and (transport != TransportType.STDIO or client == ClientType.CLAUDE_CODE)
        else []
    )

    args = entry.get("args") or []
    if not isinstance(args, list):
        args = []

    return ServerConfig(
        name=name,
        client=client,
        config_path=config_path,
        project_path=project_path,
        scope=scope,
        command=entry.get("command") or None,
        args=[str(arg) for arg in args],
        env_keys=env_keys,
        transport=transport,
        url=entry.get("url") or None,
        headers_keys=headers_keys,
    )
