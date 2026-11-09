"""Lazy, explicit collector allowlist for the optional shadow-mcp adapter.

No fallback invokes discovery with its defaults: that could read Claude Code's
credential-bearing config, call its CLI, or inspect processes.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
from collections.abc import Awaitable
from pathlib import Path
from types import ModuleType

from mcp_audit.models import ClientType, ServerConfig, TransportType
from redteam.chains.pairs import ConfiguredServer, resolve_configs

DEFAULT_COLLECTORS = ("ClaudeDesktop", "Codex", "Dxt", "ProjectMcpJson")


def _export(module: ModuleType, name: str) -> object:
    value: object = getattr(module, name, None)
    return value


def _api() -> tuple[object, ModuleType]:
    """Support the public facade or discovery/collectors module exports."""
    module = importlib.import_module("shadow_mcp")
    discover_all = _export(module, "discover_all")
    if discover_all is None:
        discover_all = _export(importlib.import_module("shadow_mcp.discovery"), "discover_all")
    try:
        collectors = importlib.import_module("shadow_mcp.collectors")
    except ModuleNotFoundError as exc:
        if exc.name != "shadow_mcp.collectors":
            raise
        collectors = module
    return discover_all, collectors


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"shadow-mcp returned invalid {field}")
    return [str(item) for item in value]


def _field(entry: object, name: str, default: object = None) -> object:
    if isinstance(entry, dict):
        value: object = entry.get(name, default)
        return value
    value = getattr(entry, name, default)
    return value


def _server(entry: object) -> ServerConfig:
    if isinstance(entry, ServerConfig):
        return entry
    name = _field(entry, "name")
    command = _field(entry, "command")
    url = _field(entry, "url")
    if not isinstance(name, str) or not name:
        raise ValueError("shadow-mcp server is missing its name")
    if command is not None and not isinstance(command, str):
        raise ValueError("shadow-mcp returned invalid command")
    if url is not None and not isinstance(url, str):
        raise ValueError("shadow-mcp returned invalid url")
    env_keys = _field(entry, "env_keys")
    if env_keys is None:
        env = _field(entry, "env", {})
        if not isinstance(env, dict) or any(not isinstance(key, str) for key in env):
            raise ValueError("shadow-mcp returned invalid environment metadata")
        env_keys = list(env)  # Values never leave the adapter.
    headers_keys = _field(entry, "headers_keys")
    if headers_keys is None:
        headers = _field(entry, "headers", {})
        if not isinstance(headers, dict) or any(not isinstance(key, str) for key in headers):
            raise ValueError("shadow-mcp returned invalid header metadata")
        headers_keys = list(headers)
    transport = _field(entry, "transport", "stdio")
    if transport not in ("stdio", "http", "sse"):
        raise ValueError("shadow-mcp returned unsupported transport")
    return ServerConfig(
        name=name,
        # The core model has no Codex/Dxt client enum. This marker is internal;
        # reports deliberately omit it rather than mislabeling those clients.
        client=ClientType.CLAUDE_CODE,
        config_path="<shadow-mcp>",
        command=command,
        args=_strings(_field(entry, "args", []), "args"),
        url=url,
        transport=TransportType(str(transport)),
        env_keys=sorted(set(_strings(env_keys, "env_keys"))),
        headers_keys=sorted(set(_strings(headers_keys, "headers_keys"))),
    )


async def _await(value: Awaitable[object]) -> object:
    return await value


def discover_servers(
    *, include_claude_code: bool = False, pins_dir: Path | None = None
) -> list[ConfiguredServer]:
    """Call discover_all exactly once with only explicitly selected collectors.

    An incompatible API fails closed; it never retries default discovery or
    invokes a CLI. Real-config discovery is for the head to exercise explicitly.
    """
    discover_all, module = _api()
    if not callable(discover_all):
        raise ValueError("shadow-mcp must expose discover_all(collectors=...)")
    signature = inspect.signature(discover_all)
    if "collectors" not in signature.parameters:
        raise ValueError("shadow-mcp must support an explicit collectors argument")
    selected: list[object] = []
    names = (*DEFAULT_COLLECTORS, "ClaudeCode") if include_claude_code else DEFAULT_COLLECTORS
    for name in names:
        factory = _export(module, name)
        if factory is None:
            factory = _export(module, f"{name}Collector")
        if not callable(factory):
            raise ValueError(f"shadow-mcp is missing its {name} collector export")
        selected.append(factory())
    discovered: object = discover_all(collectors=selected)
    if inspect.isawaitable(discovered):
        discovered = asyncio.run(_await(discovered))
    entries = _field(discovered, "servers", discovered)
    if not isinstance(entries, (list, tuple)):
        raise ValueError("shadow-mcp must return a server list or result.servers")
    configs = sorted(
        (_server(entry) for entry in entries),
        key=lambda config: (
            config.name,
            config.command or "",
            tuple(config.args),
            config.url or "",
            tuple(sorted(config.env_keys)),
        ),
    )
    # Preserve all entries rather than silently overwriting duplicate client names.
    counts: dict[str, int] = {}
    for config in configs:
        counts[config.name] = counts.get(config.name, 0) + 1
    serials: dict[str, int] = {}
    for config in configs:
        if counts[config.name] > 1:
            original = config.name
            serials[original] = serials.get(original, 0) + 1
            config.name = f"{original} [discovered entry {serials[original]}]"
    return resolve_configs(configs, pins_dir=pins_dir)
