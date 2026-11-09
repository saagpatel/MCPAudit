"""Manifest-only DXT metadata; never load extension code or environment values."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

from mcp_audit.models import ServerConfig
from redteam.surface import ServerSurface, SurfaceTool


def _default_directory() -> tuple[Path | None, str | None]:
    """Use shadow-mcp's path definition without running discovery collectors."""
    try:
        module = importlib.import_module("shadow_mcp.config")
    except ModuleNotFoundError as exc:
        if exc.name in {"shadow_mcp", "shadow_mcp.config"}:
            return None, "DXT default directory unavailable: shadow-mcp is not installed"
        raise
    paths_class: object = getattr(module, "DiscoveryPaths", None)
    default: object = getattr(paths_class, "default", None)
    if not callable(default):
        return None, "DXT default directory unavailable: incompatible DiscoveryPaths"
    paths: object = default()
    directory: object = getattr(paths, "claude_extensions_dir", None)
    if isinstance(directory, (str, Path)):
        return Path(directory), None
    return None, "DXT default directory unavailable: missing claude_extensions_dir"


def extension_directory(provenance: object) -> Path | None:
    """Accept explicit directory/path fields from shadow-mcp provenance records."""
    records = provenance if isinstance(provenance, (list, tuple)) else [provenance]
    directories: set[Path] = set()
    for record in records:
        source: object = record.get("source") if isinstance(record, dict) else getattr(record, "source", None)
        location: object = (
            record.get("location") if isinstance(record, dict) else getattr(record, "location", None)
        )
        if source == "dxt" and isinstance(location, (str, Path)):
            manifest = Path(location)
            if (
                manifest.is_absolute()
                and manifest.name == "manifest.json"
                and manifest.parent.parent.name == "Claude Extensions"
            ):
                directories.add(manifest.parent)
                continue
        for key in ("extension_dir", "extension_path", "path", "file_path", "config_path", "source_path"):
            value: object = record.get(key) if isinstance(record, dict) else getattr(record, key, None)
            if isinstance(value, (str, Path)):
                path = Path(value)
                if path.name == "manifest.json":
                    directories.add(path.parent)
                elif key in {"extension_dir", "extension_path"} or path.is_dir():
                    directories.add(path)
    return next(iter(directories)) if len(directories) == 1 else None


def _document(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("DXT metadata must be a JSON object")
    return value


def _roots(extension: Path, config: ServerConfig) -> tuple[str, ...]:
    if not any("${user_config.allowed_directories}" in arg for arg in config.args):
        return ()
    settings = extension.parent.parent / "Claude Extensions Settings" / f"{extension.name}.json"
    if not settings.exists():
        return ()
    # Only this key is retained. Reject links outside the settings directory.
    if settings.resolve().parent != settings.parent.resolve():
        raise ValueError("DXT settings escaped the selected settings directory")
    user_config = _document(settings).get("userConfig")
    allowed = user_config.get("allowed_directories") if isinstance(user_config, dict) else None
    if allowed is None:
        return ()
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        raise ValueError("DXT allowed_directories must be a list of paths")
    return tuple(sorted(set(allowed)))


def manifest_surface(
    config: ServerConfig,
    dxt_dir: Path | None,
    extension: Path | None = None,
) -> tuple[ServerSurface | None, tuple[str, ...], str | None]:
    """Resolve one exact launch manifest, or report ambiguous/unreadable metadata.

    Provenance can select a manifest directly. Otherwise placeholder arguments
    must match the manifest's command/args exactly; names alone are not identity.
    """
    if extension is None and not any("${__dirname}" in arg for arg in config.args):
        return None, (), None
    if extension is None and dxt_dir is None:
        dxt_dir, reason = _default_directory()
        if reason is not None:
            return None, (), reason
    if extension is None and (dxt_dir is None or not dxt_dir.is_dir()):
        return None, (), "DXT extension directory unavailable"
    try:
        if extension is not None:
            candidates = [extension]
        else:
            assert dxt_dir is not None
            candidates = sorted(path for path in dxt_dir.iterdir() if path.is_dir())
        matches: list[tuple[Path, dict[str, object]]] = []
        for directory in candidates:
            manifest = directory / "manifest.json"
            if not manifest.is_file():
                continue
            if manifest.resolve().parent != directory.resolve():
                raise ValueError("DXT manifest escaped the extension directory")
            if extension is None and dxt_dir is not None and directory.resolve().parent != dxt_dir.resolve():
                raise ValueError("DXT extension escaped the selected directory")
            document = _document(manifest)
            launch = document.get("server")
            if extension is not None or (
                isinstance(launch, dict)
                and launch.get("command") == config.command
                and launch.get("args") == config.args
            ):
                matches.append((directory, document))
        if len(matches) != 1:
            return None, (), "DXT manifest launch identity is ambiguous or unmatched"
        directory, document = matches[0]
        declared = document.get("tools")
        if not isinstance(declared, list) or not declared:
            return None, (), "DXT manifest has no declared tools"
        tools: list[SurfaceTool] = []
        for tool in declared:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
                raise ValueError("DXT tool name must be a nonempty string")
            description = tool.get("description")
            if description is not None and not isinstance(description, str):
                raise ValueError("DXT tool description must be a string")
            tools.append(SurfaceTool(name=tool["name"], description=description))
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("DXT manifest has duplicate tools")
        roots: tuple[str, ...] = ()
        roots_reason = None
        try:
            roots = _roots(directory, config)
        except (OSError, UnicodeError, ValueError) as exc:
            roots_reason = f"DXT roots unknown: settings unavailable or invalid ({type(exc).__name__})"
        return (
            ServerSurface(
                server_name=config.name,
                source="dxt-manifest",
                tools=sorted(tools, key=lambda tool: tool.name),
                provenance="declared by the extension manifest; schemas not declared",
                unverified=True,
            ),
            roots,
            roots_reason,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        # Neither parser excerpts nor workstation paths belong in diagnostics.
        return None, (), f"DXT metadata unavailable or invalid ({type(exc).__name__})"
