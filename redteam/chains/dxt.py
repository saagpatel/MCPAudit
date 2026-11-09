"""Manifest-only DXT metadata; never load extension code or environment values."""

from __future__ import annotations

import importlib
import io
import json
import os
import stat
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
            if manifest.is_absolute() and manifest.name == "manifest.json":
                try:
                    root = manifest.parent.parent
                    if root.name != "Claude Extensions" or ".." in manifest.parts:
                        continue
                    if manifest.exists() and manifest.resolve(strict=True) != manifest:
                        continue
                except OSError:
                    pass
                else:
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


def _document_at(root: Path, directory: str, filename: str) -> dict[str, object]:
    """Read one regular JSON file below an opened directory without following links."""
    if Path(directory).name != directory or Path(filename).name != filename:
        raise ValueError("DXT metadata path is not a direct child")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("DXT no-follow metadata reads are unavailable")
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("DXT metadata root must be canonical and absolute")
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    root_fd = os.open("/", directory_flags)
    try:
        for component in root.parts[1:]:
            child_fd = os.open(component, directory_flags, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = child_fd
        directory_fd = os.open(directory, directory_flags, dir_fd=root_fd)
        try:
            file_fd = os.open(filename, file_flags, dir_fd=directory_fd)
            with os.fdopen(file_fd, "rb") as raw:
                info = os.fstat(raw.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("DXT metadata is not a regular file")
                with io.TextIOWrapper(raw, encoding="utf-8") as stream:
                    value: object = json.load(stream)
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)
    if not isinstance(value, dict):
        raise ValueError("DXT metadata must be a JSON object")
    return value


def _roots(extension: Path, config: ServerConfig, *, required: bool = False) -> tuple[str, ...]:
    if not required and not any("${user_config.allowed_directories}" in arg for arg in config.args):
        return ()
    claude_root = extension.parent.parent
    if claude_root.resolve(strict=True) != claude_root:
        raise ValueError("DXT settings parent escaped the selected extensions directory")
    settings_root = claude_root / "Claude Extensions Settings"
    settings = settings_root / f"{extension.name}.json"
    if not os.path.lexists(settings):
        return ()
    # Both directory and file links can redirect this read to another extension.
    if settings_root.resolve(strict=True) != settings_root or settings.is_symlink():
        raise ValueError("DXT settings escaped the selected settings directory")
    user_config = _document_at(claude_root, settings_root.name, settings.name).get("userConfig")
    allowed = user_config.get("allowed_directories") if isinstance(user_config, dict) else None
    if allowed is None:
        return ()
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        raise ValueError("DXT allowed_directories must be a list of paths")
    return tuple(dict.fromkeys(allowed))


def _launch_args_match(
    manifest_args: object, config: ServerConfig, extension: Path
) -> tuple[bool, tuple[str, ...] | None]:
    if not isinstance(manifest_args, list) or any(not isinstance(item, str) for item in manifest_args):
        return False, None
    args = tuple(manifest_args)
    if args == tuple(config.args):
        return True, None
    roots: tuple[str, ...] | None = None
    states: set[tuple[int, tuple[str, ...] | None]] = {(0, None)}
    for argument in args:
        options: list[tuple[tuple[str, ...], tuple[str, ...] | None]]
        if argument == "${user_config.allowed_directories}":
            try:
                roots = _roots(extension, config, required=True)
            except (OSError, UnicodeError, ValueError):
                roots = None
            options = [((argument,), None)]
            if roots:
                options.append((roots, roots))
        elif "${user_config.allowed_directories}" in argument:
            return False, None
        elif "${__dirname}" in argument:
            if argument.count("${__dirname}") != 1:
                return False, None
            expanded = argument.replace("${__dirname}", str(extension.resolve(strict=True)))
            options = [((argument,), None), ((expanded,), None)]
        else:
            # Other literal placeholders can match only when the discovered
            # launch spec retained the same token.
            options = [((argument,), None)]
        next_states: set[tuple[int, tuple[str, ...] | None]] = set()
        for offset, roots_used in states:
            for values, option_roots in options:
                end = offset + len(values)
                if tuple(config.args[offset:end]) == values:
                    next_states.add((end, option_roots or roots_used))
        states = next_states
        if not states:
            return False, None
    for offset, roots_used in states:
        if offset == len(config.args):
            return True, roots_used
    return False, None


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
            directory = extension.resolve(strict=True)
            if not directory.is_dir() or directory != extension.absolute():
                raise ValueError("DXT extension is not a directory")
            root_candidate = next(
                (parent for parent in extension.parents if parent.name == "Claude Extensions"),
                None,
            )
            if root_candidate is None:
                raise ValueError("DXT extension is outside the selected directory")
            root = root_candidate.resolve(strict=True)
            if directory.parent != root:
                raise ValueError("DXT extension escaped the selected directory")
            if dxt_dir is not None:
                if not dxt_dir.is_dir() or root != dxt_dir.resolve(strict=True):
                    raise ValueError("DXT extension escaped the selected directory")
            candidates = [directory]
        else:
            assert dxt_dir is not None
            root = dxt_dir.resolve(strict=True)
            candidates = sorted(path.resolve(strict=True) for path in root.iterdir() if path.is_dir())
        matches: list[tuple[Path, dict[str, object], tuple[str, ...] | None]] = []
        for directory in candidates:
            manifest = directory / "manifest.json"
            if not manifest.is_file():
                continue
            resolved_manifest = manifest.resolve(strict=True)
            if resolved_manifest != manifest or resolved_manifest.parent != directory:
                raise ValueError("DXT manifest escaped the extension directory")
            if directory.parent != root:
                raise ValueError("DXT extension escaped the selected directory")
            document = _document_at(root, directory.name, manifest.name)
            launch = document.get("server")
            if not isinstance(launch, dict) or launch.get("command") != config.command:
                continue
            matched, expanded_roots = _launch_args_match(launch.get("args"), config, directory)
            if matched:
                matches.append((directory, document, expanded_roots))
        if len(matches) != 1:
            return None, (), "DXT manifest launch identity is ambiguous or unmatched"
        directory, document, expanded_roots = matches[0]
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
        roots: tuple[str, ...] = expanded_roots or ()
        roots_reason = None
        if expanded_roots is None:
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
