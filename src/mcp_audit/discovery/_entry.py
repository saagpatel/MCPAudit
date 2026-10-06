"""Shared parsing for individual MCP server config entries."""

from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from mcp_audit.discovery._config import record_issue
from mcp_audit.discovery.base import ConfigParseError, is_project_config
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


def parse_server_map(
    servers: object,
    config_path: str,
    client: ClientType,
    parse_errors: list[ConfigParseError] | None = None,
    project_path: str | None = None,
) -> list[ServerConfig]:
    """Keep valid sibling entries and report malformed entries without their values."""
    if not isinstance(servers, dict):
        raise ConfigParseError(config_path, client, "server map is not an object")
    results: list[ServerConfig] = []
    for name, entry in servers.items():
        reason = None
        if not isinstance(name, str) or not isinstance(entry, dict):
            reason = "server entry must be an object with a string name"
        else:
            for field in ("command", "url", "type"):
                if field in entry and not isinstance(entry[field], str):
                    reason = f"{field} must be a string"
                    break
            if "args" in entry and (
                not isinstance(entry["args"], list) or any(not isinstance(arg, str) for arg in entry["args"])
            ):
                reason = "args must be a list of strings"
            for field in ("env", "headers"):
                if field in entry and not isinstance(entry[field], dict):
                    reason = f"{field} must be an object"
            if reason is None:
                try:
                    results.append(
                        parse_server_entry(
                            name,
                            entry,
                            config_path,
                            client,
                            project_path,
                            scope="project"
                            if project_path is not None or is_project_config(Path(config_path))
                            else "workstation",
                        )
                    )
                    continue
                except ValidationError:
                    reason = "server entry failed validation"
        record_issue(
            ConfigParseError(
                config_path,
                client,
                reason,
                finding_type="malformed_server_entry",
                server_name=name if isinstance(name, str) else None,
            ),
            parse_errors,
        )
    return results
