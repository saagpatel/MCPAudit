"""Bounded, non-executing discovery for the additive review commands."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.discovery import _DISCOVERERS
from mcp_audit.discovery._config import decode_config
from mcp_audit.discovery._entry import parse_server_map
from mcp_audit.discovery.base import ConfigParseError
from mcp_audit.discovery.claude_code import parse_mapping
from mcp_audit.models import ClientType, ServerConfig

MAX_CONFIG_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_CONTAINERS = 20_000
MAX_SERVERS = 1_000


@dataclass
class ReviewSources:
    servers: list[ServerConfig] = field(default_factory=list)
    errors: list[ConfigParseError] = field(default_factory=list)
    paths: list[tuple[str, str]] = field(default_factory=list)


def _check_structure(text: str) -> None:
    """Bound nesting before decoding JSONC, ignoring strings and comments."""
    depth = containers = index = 0
    quote = ""
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in ('"', "'"):
            quote = char
        elif text.startswith("//", index):
            index += 2
            while index < len(text) and text[index] not in "\r\n\u2028\u2029":
                index += 1
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        elif char in "{[":
            depth += 1
            containers += 1
            if depth > MAX_DEPTH or containers > MAX_CONTAINERS:
                raise ValueError("config exceeds nesting or container limit")
        elif char in "}]":
            depth -= 1
        index += 1


def _read_bounded(path: Path, *, explicit: bool) -> str:
    if explicit:
        path = path.resolve(strict=True)
    elif any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink skipped; select it explicitly with --config")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("config path is not a regular file")
        if info.st_size > MAX_CONFIG_BYTES:
            raise ValueError("config exceeds 1 MiB limit")
        content = stream.read(MAX_CONFIG_BYTES + 1)
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("config exceeds 1 MiB limit")
    text = content.decode("utf-8-sig")
    _check_structure(text)
    return text


def _parse_source(
    path: Path,
    client: ClientType,
    sources: ReviewSources,
    project: Path,
    *,
    explicit: bool,
) -> list[ServerConfig]:
    text = _read_bounded(path, explicit=explicit)
    data = decode_config(
        text,
        str(path),
        client,
        sources.errors,
        jsonc=explicit or client in (ClientType.CURSOR, ClientType.VSCODE),
    )
    if (
        not explicit
        and client == ClientType.CLAUDE_CODE
        and path.name != ".claude.json"
        and not any(key in data for key in ("mcpServers", "projects"))
    ):
        raise ValueError("unsupported config: no MCP server map")
    if not explicit and client == ClientType.CLAUDE_CODE:
        # Only the selected project's MCP section is admitted. Never traverse
        # other project paths recorded in the global client file.
        projects = data.get("projects")
        if isinstance(projects, dict):
            selected = {str(project): projects[str(project)]} if str(project) in projects else {}
            if len(projects) > len(selected):
                sources.paths.append((str(path), "skipped other project scopes; use --project PATH"))
            data["projects"] = selected
    if explicit or client == ClientType.CLAUDE_CODE:
        servers = parse_mapping(data, str(path), sources.errors, sniff_format=explicit)
    else:
        servers = []
        maps: list[tuple[object, str]] = []
        keys = ("mcpServers", "servers") if client == ClientType.VSCODE else ("mcpServers",)
        maps.extend((data[key], f"/{key}") for key in keys if key in data)
        if client == ClientType.VSCODE and "mcp" in data:
            section = data["mcp"]
            if not isinstance(section, dict):
                raise ValueError("mcp section is not an object")
            if "servers" in section:
                maps.append((section["servers"], "/mcp/servers"))
        if not maps and not (client == ClientType.VSCODE and path.name == "settings.json"):
            raise ValueError("unsupported config: no MCP server map")
        for mapping, pointer in maps:
            servers.extend(parse_server_map(mapping, str(path), client, sources.errors, map_pointer=pointer))
    if (
        client == ClientType.CURSOR
        and path == project / ".cursor" / "mcp.json"
        and path != Path.home() / ".cursor" / "mcp.json"
    ):
        servers = [server.model_copy(update={"scope": "project"}) for server in servers]
    if len(servers) + len(sources.servers) > MAX_SERVERS:
        raise ValueError("config exceeds 1000-server review limit")
    if explicit:
        servers = [
            server.model_copy(update={"config_source": "explicit file; parsed as Claude-style config"})
            for server in servers
        ]
    return servers


def review_sources(
    config: Path | None = None,
    include_discovered: bool = False,
    project: Path | None = None,
) -> ReviewSources:
    """Read an explicit file only, or the fixed supported-client allowlist."""
    sources = ReviewSources()
    project = Path(os.path.abspath(project or Path.cwd()))
    candidates: list[tuple[Path, ClientType, bool]] = []
    if config is not None:
        candidates.append((config, ClientType.CLAUDE_CODE, True))
    if config is None or include_discovered:
        for client, discoverer in _DISCOVERERS.items():
            for path in discoverer().config_paths():
                if path == Path.cwd() / ".mcp.json":
                    path = project / ".mcp.json"
                elif path == Path.cwd() / ".vscode" / "mcp.json":
                    path = project / ".vscode" / "mcp.json"
                candidates.append((path, client, False))
        cursor_project = project / ".cursor" / "mcp.json"
        if cursor_project != Path.home() / ".cursor" / "mcp.json":
            candidates.append((cursor_project, ClientType.CURSOR, False))
    seen: set[Path] = set()
    for path, client, explicit in candidates:
        identity = path.absolute()
        if identity in seen:
            continue
        seen.add(identity)
        try:
            if not explicit:
                # Missing adapter candidates are not evidence to open or parse.
                path.lstat()
            servers = _parse_source(path, client, sources, project, explicit=explicit)
        except FileNotFoundError:
            if explicit:
                raise ValueError(f"Config file not found: {path}") from None
            sources.paths.append((str(path), "absent"))
        except (OSError, UnicodeError, ValueError, ConfigParseError) as exc:
            reason = (
                exc.reason
                if isinstance(exc, ConfigParseError)
                else (
                    str(exc)
                    if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError)
                    else f"unreadable config: {type(exc).__name__}"
                )
            )
            if explicit:
                raise ValueError(f"Cannot review {path}: {reason}") from None
            sources.errors.append(ConfigParseError(str(path), client, reason))
            sources.paths.append((str(path), f"skipped: {reason}"))
        else:
            sources.servers.extend(servers)
            label = "; explicit file; parsed as Claude-style config" if explicit else ""
            sources.paths.append((str(path), f"checked: {len(servers)} entries{label}"))
    return sources


def server_identity(server: ServerConfig) -> str:
    return f"{server.client.value}:{server.scope}:{server.name}"
