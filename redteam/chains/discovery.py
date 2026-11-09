"""Explicit, read-only shadow-mcp collector adapter."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from types import ModuleType

import mcp_audit
from mcp_audit.models import ClientType, ServerConfig, TransportType
from redteam.chains.dxt import extension_directory
from redteam.chains.pairs import ConfiguredServer, resolve_configs

DEFAULT_COLLECTORS = (
    ("claude_desktop", "ClaudeDesktopCollector"),
    ("codex", "CodexCollector"),
    ("dxt", "DxtCollector"),
    ("project_mcp", "ProjectMcpJsonCollector"),
)


class ShadowImportError(ImportError):
    """An absent or incompatible optional shadow-mcp installation."""


class DiscoveryServers(list[ConfiguredServer]):
    """Resolved servers with discovery diagnostics available to the caller."""

    def __init__(self, servers: list[ConfiguredServer], notes: list[str]) -> None:
        super().__init__(servers)
        self.notes = notes


def _module(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name == "shadow_mcp":
            raise ShadowImportError(
                "set PYTHONPATH=<path-to-shadow-mcp>/src and use uv run --locked ..."
            ) from exc
        raise ShadowImportError(f"incompatible shadow-mcp: missing module {exc.name}") from exc
    except ImportError as exc:
        raise ShadowImportError(f"incompatible shadow-mcp: cannot import {name}") from exc


def _required(module: ModuleType, name: str) -> object:
    value: object = getattr(module, name, None)
    if value is None:
        raise ShadowImportError(f"incompatible shadow-mcp: missing {module.__name__}.{name}")
    return value


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"shadow-mcp returned invalid {field}")
    return [str(item) for item in value]


def _server(entry: object) -> ServerConfig:
    name: object = getattr(entry, "name", None)
    spec: object = getattr(entry, "spec", None)
    if not isinstance(name, str) or not name or spec is None:
        raise ValueError("shadow-mcp server is missing its name or spec")
    command: object = getattr(spec, "command", None)
    url: object = getattr(spec, "url", None)
    transport: object = getattr(spec, "transport", None)
    if command is not None and not isinstance(command, str):
        raise ValueError("shadow-mcp returned invalid command")
    if url is not None and not isinstance(url, str):
        raise ValueError("shadow-mcp returned invalid url")
    if transport not in ("stdio", "http", "sse"):
        raise ValueError("shadow-mcp returned unsupported transport")
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path="<shadow-mcp>",
        command=command,
        args=_strings(getattr(spec, "args", None), "args"),
        url=url,
        transport=TransportType(str(transport)),
        env_keys=sorted(set(_strings(getattr(spec, "env_keys", None), "env_keys"))),
    )


def _provenance(entry: object) -> tuple[str | None, str | None]:
    record: object = getattr(entry, "provenance", None)
    source: object = record.get("source") if isinstance(record, dict) else getattr(record, "source", None)
    location: object = (
        record.get("location") if isinstance(record, dict) else getattr(record, "location", None)
    )
    if source is not None and not isinstance(source, str):
        raise ValueError("shadow-mcp returned invalid provenance source")
    if location is not None and not isinstance(location, (str, Path)):
        raise ValueError("shadow-mcp returned invalid provenance location")
    return source, str(location) if location is not None else None


def discover_servers(
    *, include_claude_code: bool = False, pins_dir: Path | None = None, dxt_dir: Path | None = None
) -> list[ConfiguredServer]:
    """Run only explicitly allowlisted collectors; never fall back to defaults."""
    module_file = mcp_audit.__file__
    repo_src = Path(__file__).resolve().parents[2] / "src"
    if module_file is None or not Path(module_file).resolve().is_relative_to(repo_src):
        raise ShadowImportError("mcp_audit must be imported from this checkout's src/ directory")
    _module("shadow_mcp")
    paths_class = _required(_module("shadow_mcp.config"), "DiscoveryPaths")
    default: object = getattr(paths_class, "default", None)
    discover = _required(_module("shadow_mcp.collectors.base"), "discover_all")
    if not callable(default):
        raise ShadowImportError("incompatible shadow-mcp: missing DiscoveryPaths.default")
    if not callable(discover):
        raise ShadowImportError("incompatible shadow-mcp: discover_all is not callable")
    try:
        inspect.signature(discover).bind(None, include_processes=False, include_cli=False, collectors=[])
    except (TypeError, ValueError) as exc:
        raise ShadowImportError("incompatible shadow-mcp: discover_all signature") from exc
    names: tuple[tuple[str, str], ...] = DEFAULT_COLLECTORS
    if include_claude_code:
        names += (("claude_code", "ClaudeCodeCollector"),)
    factories = [_required(_module(f"shadow_mcp.collectors.{module}"), name) for module, name in names]
    if any(not callable(factory) for factory in factories):
        raise ShadowImportError("incompatible shadow-mcp: collector is not callable")
    paths: object = default()
    selected = [factory(paths) for factory in factories if callable(factory)]
    result: object = discover(paths, include_processes=False, include_cli=False, collectors=selected)
    entries: object = getattr(result, "servers", None)
    counts: object = getattr(result, "source_counts", None)
    errors: object = getattr(result, "errors", None)
    if not isinstance(entries, list) or not isinstance(counts, dict):
        raise ShadowImportError("incompatible shadow-mcp: missing result servers or source_counts")
    if any(not isinstance(k, str) or not isinstance(v, int) for k, v in counts.items()):
        raise ValueError("shadow-mcp returned invalid source_counts")
    notes = [f"shadow-mcp source {key}: {counts[key]}" for key in sorted(counts)]
    notes.extend(f"shadow-mcp error: {error}" for error in _strings(errors, "errors"))
    if dxt_dir is None:
        default_dir: object = getattr(paths, "claude_extensions_dir", None)
        if isinstance(default_dir, (str, Path)):
            dxt_dir = Path(default_dir)
    extension_paths: dict[tuple[str, str | None, tuple[str, ...], str | None], Path] = {}
    provenance_paths: dict[
        tuple[str, str | None, tuple[str, ...], str | None], tuple[str | None, str | None]
    ] = {}
    for entry in entries:
        config = _server(entry)
        key = (config.name, config.command, tuple(config.args), config.url)
        provenance = _provenance(entry)
        directory = extension_directory(getattr(entry, "provenance", None))
        # Keep provenance associated with the selected extension when duplicate
        # launch identities are also seen by a non-DXT collector.
        if key not in provenance_paths or directory is not None:
            provenance_paths[key] = provenance
        if directory is not None:
            previous = extension_paths.get(key)
            if previous is not None and previous != directory:
                raise ValueError("conflicting DXT provenance for the same launch identity")
            extension_paths[key] = directory
    configs = sorted(
        (_server(entry) for entry in entries),
        key=lambda config: (
            config.name,
            config.command or "",
            tuple(config.args),
            config.url or "",
            tuple(config.env_keys),
        ),
    )
    unique: dict[tuple[str, str | None, tuple[str, ...], str | None], ServerConfig] = {}
    for config in configs:
        key = (config.name, config.command, tuple(config.args), config.url)
        unique.setdefault(key, config)
    configs = list(unique.values())
    name_counts: dict[str, int] = {}
    for config in configs:
        name_counts[config.name] = name_counts.get(config.name, 0) + 1
    serials: dict[str, int] = {}
    extensions: dict[str, Path] = {}
    sources: dict[str, tuple[str | None, str | None]] = {}
    for config in configs:
        key = (config.name, config.command, tuple(config.args), config.url)
        directory = extension_paths.get(key)
        if name_counts[config.name] > 1:
            original = config.name
            serials[original] = serials.get(original, 0) + 1
            config.name = f"{original} [discovered entry {serials[original]}]"
        if directory is not None:
            extensions[config.name] = directory
        sources[config.name] = provenance_paths[key]
    return DiscoveryServers(
        resolve_configs(
            configs, pins_dir=pins_dir, dxt_dir=dxt_dir, extensions=extensions, provenance=sources
        ),
        notes,
    )
