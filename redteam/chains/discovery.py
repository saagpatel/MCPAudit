"""Explicit, read-only shadow-mcp collector adapter (never default collectors)."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable
from copy import copy
from dataclasses import is_dataclass, replace
from pathlib import Path
from types import ModuleType

from mcp_audit.models import ClientType, ServerConfig, TransportType
from redteam.catalog import CATALOG, CATALOG_FILES
from redteam.chains import ShadowImportError as ShadowImportError
from redteam.chains import ensure_repo_import
from redteam.chains.dxt import extension_directory, metadata_inputs
from redteam.chains.pairs import ConfiguredServer, resolve_configs

DEFAULT_COLLECTORS = (
    ("claude_desktop", "ClaudeDesktopCollector"),
    ("codex", "CodexCollector"),
    ("dxt", "DxtCollector"),
    ("project_mcp", "ProjectMcpJsonCollector"),
)
KNOWN_SOURCE_KEYS = frozenset(module for module, _ in DEFAULT_COLLECTORS) | {"claude_code"}


class DiscoveryServers(list[ConfiguredServer]):
    """Resolved servers with discovery diagnostics available to the caller."""

    def __init__(
        self,
        servers: list[ConfiguredServer],
        notes: list[str],
        source_counts: dict[str, int],
        collector_errors: list[str],
    ) -> None:
        super().__init__(servers)
        self.notes = notes
        self.source_counts = source_counts
        self.collector_errors = collector_errors


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
        headers_keys=sorted(set(_strings(getattr(spec, "headers_keys", []), "headers_keys"))),
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


def _protect_source_paths(entry: object, input_paths: list[Path]) -> None:
    """Protect reported source paths without opening any extra input files."""
    for record in (entry, getattr(entry, "provenance", None)):
        for field in ("location", "config_path", "source_path", "file_path", "path"):
            value: object = record.get(field) if isinstance(record, dict) else getattr(record, field, None)
            if isinstance(value, (str, Path)) and str(value):
                input_paths.append(Path(value))


def _path(paths: object, field: str) -> Path:
    value: object = getattr(paths, field, None)
    if not isinstance(value, (str, Path)) or not str(value):
        raise ShadowImportError(f"incompatible shadow-mcp: missing DiscoveryPaths.{field}")
    return Path(value)


def _protect_configured_paths(
    paths: object,
    include_claude_code: bool,
    input_paths: list[Path],
    input_directories: list[Path],
) -> None:
    """Register collector inputs even if parsing fails or returns no servers."""
    input_paths.extend(_path(paths, field) for field in ("claude_desktop_config", "codex_config"))
    profiles = _path(paths, "codex_profiles_dir")
    input_paths.extend(sorted(profiles.glob("*.toml")))
    input_paths.extend(sorted(profiles.glob("*/config.toml")))
    projects = _path(paths, "projects_root")
    input_paths.extend(sorted(projects.rglob(".mcp.json")))
    if include_claude_code:
        input_paths.append(_path(paths, "claude_code_config"))
    extensions = _path(paths, "claude_extensions_dir")
    # The collector uses its configured settings path; manifest resolution also
    # reads the conventional sibling directory. Protect both if they differ.
    settings_roots = {
        _path(paths, "claude_extensions_settings_dir"),
        extensions.parent / "Claude Extensions Settings",
    }
    input_directories.append(extensions)
    for settings in sorted(settings_roots):
        input_directories.append(settings)
        input_paths.extend(metadata_inputs(extensions, settings))


def discover_servers(
    *,
    include_claude_code: bool = False,
    pins_dir: Path | None = None,
    dxt_dir: Path | None = None,
    input_paths: list[Path] | None = None,
    input_directories: list[Path] | None = None,
    validate_inputs: Callable[[], None] | None = None,
) -> list[ConfiguredServer]:
    """Run only explicitly allowlisted collectors; never fall back to defaults."""
    ensure_repo_import()
    input_paths = input_paths if input_paths is not None else []
    input_directories = input_directories if input_directories is not None else []
    input_paths.extend(CATALOG / name for name in CATALOG_FILES.values())
    if pins_dir is not None:
        input_paths.extend(
            pins_dir / name for name in (".mcp-audit-pins.yaml", "signing-key.pem", "trusted-keys.yaml")
        )
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
    if dxt_dir is not None:
        overrides = {
            "claude_extensions_dir": dxt_dir,
            "claude_extensions_settings_dir": dxt_dir.parent / "Claude Extensions Settings",
        }
        try:
            if is_dataclass(paths) and not isinstance(paths, type):
                paths = replace(paths, **overrides)
            else:
                paths = copy(paths)
                for field, value in overrides.items():
                    setattr(paths, field, value)
        except (AttributeError, TypeError) as exc:
            raise ShadowImportError("incompatible shadow-mcp: DiscoveryPaths DXT fields") from exc
    dxt_dir = _path(paths, "claude_extensions_dir")
    _protect_configured_paths(paths, include_claude_code, input_paths, input_directories)
    if validate_inputs is not None:
        validate_inputs()
    selected = [factory(paths) for factory in factories if callable(factory)]
    result: object = discover(paths, include_processes=False, include_cli=False, collectors=selected)
    entries: object = getattr(result, "servers", None)
    counts: object = getattr(result, "source_counts", None)
    errors: object = getattr(result, "errors", None)
    if not isinstance(entries, list) or not isinstance(counts, dict):
        raise ShadowImportError("incompatible shadow-mcp: missing result servers or source_counts")
    if any(not isinstance(k, str) or type(v) is not int or v < 0 for k, v in counts.items()):
        raise ValueError("shadow-mcp returned invalid source_counts")
    notes = [f"shadow-mcp source {key}: {counts[key]}" for key in sorted(counts) if key in KNOWN_SOURCE_KEYS]
    unknown_count = sum(count for key, count in counts.items() if key not in KNOWN_SOURCE_KEYS)
    if unknown_count:
        notes.append(f"shadow-mcp source (unrecognized): {unknown_count}")
    collector_errors = ["shadow-mcp collector error (details withheld)" for _ in _strings(errors, "errors")]
    notes.extend(collector_errors)
    source_counts = {key: counts[key] for key in sorted(counts) if key in KNOWN_SOURCE_KEYS}
    if unknown_count:
        source_counts["unrecognized"] = unknown_count
    extension_paths: dict[tuple[str, str | None, tuple[str, ...], str | None], Path] = {}
    provenance_paths: dict[
        tuple[str, str | None, tuple[str, ...], str | None], tuple[str | None, str | None]
    ] = {}
    for entry in entries:
        config = _server(entry)
        key = (config.name, config.command, tuple(config.args), config.url)
        provenance = _provenance(entry)
        _protect_source_paths(entry, input_paths)
        directory = extension_directory(getattr(entry, "provenance", None))
        if provenance[0] == "dxt" and directory is None:
            raise ValueError("DXT provenance must name a direct-child extension manifest")
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
        previous_config = unique.get(key)
        if previous_config is not None and (
            previous_config.transport != config.transport
            or previous_config.env_keys != config.env_keys
            or previous_config.headers_keys != config.headers_keys
        ):
            raise ValueError("conflicting metadata for duplicate discovered launch identity")
        unique.setdefault(key, config)
    configs = list(unique.values())
    name_counts: dict[str, int] = {}
    for config in configs:
        name_counts[config.name] = name_counts.get(config.name, 0) + 1
    serials: dict[str, int] = {}
    extensions: dict[str, Path] = {}
    resolved: list[ConfiguredServer] = []
    used_names = {config.name for config in configs}
    for config in configs:
        key = (config.name, config.command, tuple(config.args), config.url)
        directory = extension_paths.get(key)
        display_name = config.name
        if name_counts[config.name] > 1:
            original = config.name
            while True:
                serials[original] = serials.get(original, 0) + 1
                display_name = f"{original} [discovered entry {serials[original]}]"
                if display_name not in used_names:
                    used_names.add(display_name)
                    break
        if directory is not None:
            extensions[display_name] = directory
        # Resolve with the original configured name: display disambiguation must
        # not bypass a same-name pin's mismatch or persisted missing-entry gate.
        server = resolve_configs(
            [config],
            pins_dir=pins_dir,
            dxt_dir=dxt_dir,
            extensions={config.name: directory} if directory is not None else {},
            provenance={config.name: provenance_paths[key]},
            input_paths=input_paths,
        )[0]
        resolved.append(
            replace(
                server,
                name=display_name,
                surface=server.surface.model_copy(update={"server_name": display_name})
                if server.surface is not None
                else None,
            )
        )
    roots = {directory.parent for directory in extensions.values()}
    for root in sorted(roots):
        settings = root.parent / "Claude Extensions Settings"
        input_directories.extend([root, settings])
        input_paths.extend(metadata_inputs(root, settings))
    return DiscoveryServers(
        resolved,
        notes,
        source_counts,
        collector_errors,
    )
