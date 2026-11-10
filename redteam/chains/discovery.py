"""Explicit, read-only shadow-mcp collector adapter (never default collectors)."""

from __future__ import annotations

import importlib
import inspect
import json
import tomllib
from collections.abc import Callable
from dataclasses import is_dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import Literal

from mcp_audit.models import ClientType, ServerConfig, TransportType
from redteam.catalog import CATALOG, CATALOG_FILES
from redteam.chains import ShadowImportError as ShadowImportError
from redteam.chains import ensure_repo_import
from redteam.chains.dxt import DxtCollector, extension_directory, metadata_inputs, read_regular_file
from redteam.chains.pairs import ConfiguredServer, resolve_configs

DEFAULT_COLLECTORS = (
    ("claude_desktop", "ClaudeDesktopCollector"),
    ("codex", "CodexCollector"),
    ("project_mcp", "ProjectMcpJsonCollector"),
)
KNOWN_SOURCE_KEYS = frozenset(module for module, _ in DEFAULT_COLLECTORS) | {"claude_code", "dxt"}


class DiscoveredConfig(ServerConfig):
    """Keep unavailable discovery metadata distinct from an explicit empty list."""

    header_keys_state: Literal["AVAILABLE", "UNAVAILABLE"]


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


def _server(entry: object) -> DiscoveredConfig:
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
    return DiscoveredConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path="<shadow-mcp>",
        command=command,
        args=_strings(getattr(spec, "args", None), "args"),
        url=url,
        transport=TransportType(str(transport)),
        env_keys=sorted(set(_strings(getattr(spec, "env_keys", None), "env_keys"))),
        headers_keys=sorted(set(_strings(getattr(spec, "headers_keys", []), "headers_keys"))),
        header_keys_state="UNAVAILABLE" if transport in ("http", "sse") else "AVAILABLE",
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
) -> list[tuple[str, Path]]:
    """Register collector inputs even if parsing fails or returns no servers."""
    selected = [(field, _path(paths, field)) for field in ("claude_desktop_config", "codex_config")]
    profiles: object = getattr(paths, "codex_profile_configs", None)
    if not isinstance(profiles, list) or any(not isinstance(item, Path) for item in profiles):
        raise ShadowImportError("incompatible shadow-mcp: invalid DiscoveryPaths.codex_profile_configs")
    selected.extend(("codex_profile_config", path) for path in profiles)
    projects: object = getattr(paths, "projects_root", None)
    depth: object = getattr(paths, "project_glob_depth", None)
    if (projects is not None and not isinstance(projects, Path)) or type(depth) is not int:
        raise ShadowImportError("incompatible shadow-mcp: invalid DiscoveryPaths project settings")
    if isinstance(projects, Path):
        selected.extend(("project_config", path) for path in _project_files(projects, depth))
    if include_claude_code:
        selected.append(("claude_code_config", _path(paths, "claude_json")))
    input_paths.extend(path for _, path in selected)
    extensions = _path(paths, "claude_extensions_dir")
    settings = extensions.parent / "Claude Extensions Settings"
    input_directories.extend([extensions, settings])
    input_paths.extend(metadata_inputs(extensions, settings))
    return selected


def _validate_server_map(block: object, kind: str, field: str) -> tuple[int, list[str]]:
    """Validate launch shapes without putting configuration values in errors."""
    if not isinstance(block, dict):
        return 0, [f"{kind} collector error: field {field} (TypeError)"]
    errors: list[str] = []
    valid = 0
    for name, entry in sorted(block.items()):
        prefix = f"{kind} collector error: entry {json.dumps(name)}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} field {field} (TypeError)")
            continue
        invalid: list[str] = []
        url_fields = ("url",) if kind.startswith("codex") else ("url", "serverUrl", "endpoint")
        for key in ("command", *url_fields):
            if key in entry and not isinstance(entry[key], str):
                invalid.append(key)
        if "args" in entry and (
            not isinstance(entry["args"], list) or any(not isinstance(arg, str) for arg in entry["args"])
        ):
            invalid.append("args")
        for key in ("env", "headers"):
            if key in entry and (
                not isinstance(entry[key], dict) or any(not isinstance(item, str) for item in entry[key])
            ):
                invalid.append(key)
        # JSON collectors call .lower() on these fields before inferring transport.
        if not kind.startswith("codex"):
            for key in ("type", "transport"):
                if key in entry and not isinstance(entry[key], str):
                    invalid.append(key)
        errors.extend(f"{prefix} field {key} (TypeError)" for key in invalid)
        if not entry.get("command") and not any(entry.get(key) for key in url_fields):
            errors.append(f"{prefix} field command/url (ValueError)")
        elif not invalid:
            valid += 1
    return valid, errors


def _validate_config_files(
    selected: list[tuple[str, Path]],
) -> tuple[list[str], set[str], dict[tuple[str, Path], int]]:
    """Detect errors hidden by fail-soft collectors without retaining values."""
    errors: list[str] = []
    blocked: set[str] = set()
    expected: dict[tuple[str, Path], int] = {}
    sources = {
        "claude_desktop_config": "claude_desktop",
        "codex_config": "codex",
        "codex_profile_config": "codex",
        "project_config": "project_mcp",
        "claude_code_config": "claude_code",
    }
    for kind, path in sorted(selected):
        try:
            content = read_regular_file(path)
            document: object = tomllib.loads(content) if path.suffix == ".toml" else json.loads(content)
            if not isinstance(document, dict):
                raise ValueError("config must be an object")
            field = "mcp_servers" if kind.startswith("codex") else "mcpServers"
            count, shape_errors = _validate_server_map(document.get(field, {}), kind, field)
            if kind == "claude_code_config" and "projects" in document:
                projects = document["projects"]
                if not isinstance(projects, dict):
                    shape_errors.append(f"{kind} collector error: field projects (TypeError)")
                else:
                    for project in projects.values():
                        if not isinstance(project, dict):
                            shape_errors.append(f"{kind} collector error: field projects entry (TypeError)")
                            continue
                        project_count, project_errors = _validate_server_map(
                            project.get(field, {}), kind, f"projects.{field}"
                        )
                        count += project_count
                        shape_errors.extend(project_errors)
            errors.extend(shape_errors)
            if shape_errors:
                blocked.add(sources[kind])
            expected[(kind, path)] = count
        except FileNotFoundError:
            continue  # Absent inputs are normal, including absent parent dirs.
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            errors.append(f"{kind} collector error ({type(exc).__name__})")
            blocked.add(sources[kind])
    return errors, blocked, expected


def _dropped_entries(
    entries: list[object], expected: dict[tuple[str, Path], int], blocked: set[str]
) -> list[str]:
    """Compare sightings before deduplication, using each collector's provenance."""
    sources = {
        "claude_desktop_config": ("claude_desktop", "claude_desktop"),
        "codex_config": ("codex", "codex"),
        "codex_profile_config": ("codex", "codex"),
        "project_config": ("project_mcp", "project_mcp_json"),
        "claude_code_config": ("claude_code", "claude_code"),
    }
    observed: dict[tuple[str | None, str | None], int] = {}
    for entry in entries:
        source, location = _provenance(entry)
        if source == "claude_code" and location is not None:
            location = location.split("#projects.", 1)[0]
        key = (source, location)
        observed[key] = observed.get(key, 0) + 1
    errors: list[str] = []
    for (kind, path), count in sorted(expected.items()):
        module, source = sources[kind]
        if module in blocked:
            continue
        difference = count - observed.get((source, str(path)), 0)
        if difference > 0:
            errors.append(f"{kind} collector dropped {difference} entries")
        elif difference < 0:
            errors.append(f"{kind} collector returned {-difference} unexpected entries")
    return errors


def _project_files(root: Path, depth: int) -> list[Path]:
    """Mirror shadow-mcp's bounded project collector, including its file cap."""
    skipped = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__", "target"}
    found: list[Path] = []
    stack = [root]
    while stack and len(found) < 200:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if (entry.name in skipped or entry.name.startswith(".")) and entry.name not in {
                        ".cursor",
                        ".vscode",
                    }:
                        continue
                    if len(entry.parts) - len(root.parts) < depth:
                        stack.append(entry)
                elif entry.name in (".mcp.json", "mcp.json"):
                    found.append(entry)
            except OSError:
                continue
    return found


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
        try:
            if is_dataclass(paths) and not isinstance(paths, type):
                paths = replace(paths, claude_extensions_dir=dxt_dir)
            else:
                raise TypeError("DiscoveryPaths must be a dataclass")
        except (AttributeError, TypeError) as exc:
            raise ShadowImportError("incompatible shadow-mcp: DiscoveryPaths DXT fields") from exc
    dxt_dir = _path(paths, "claude_extensions_dir")
    config_files = _protect_configured_paths(paths, include_claude_code, input_paths, input_directories)
    if validate_inputs is not None:
        validate_inputs()
    validation_errors, blocked, expected = _validate_config_files(config_files)
    # Never hand a rejected file to a fail-soft collector's unbounded reader.
    selected = [
        factory(paths)
        for (module, _), factory in zip(names, factories, strict=True)
        if callable(factory) and module not in blocked
    ]
    dxt_collector = DxtCollector(dxt_dir)
    selected.insert(2, dxt_collector)
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
    collector_errors.extend(validation_errors)
    collector_errors.extend(_dropped_entries(entries, expected, blocked))
    collector_errors.extend(dxt_collector.errors)
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
    unique: dict[tuple[str, str | None, tuple[str, ...], str | None], DiscoveredConfig] = {}
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
