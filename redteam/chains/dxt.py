"""Read only DXT manifests and their single allowlisted settings key."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

from mcp_audit.models import ServerConfig
from redteam.surface import ServerSurface, SurfaceTool


def extension_directory(provenance: object) -> Path | None:
    """Return a DXT manifest's parent only when it has the required layout."""
    records = provenance if isinstance(provenance, (list, tuple)) else [provenance]
    directories: set[Path] = set()
    for record in records:
        source: object = record.get("source") if isinstance(record, dict) else getattr(record, "source", None)
        location: object = (
            record.get("location") if isinstance(record, dict) else getattr(record, "location", None)
        )
        if source != "dxt" or not isinstance(location, (str, Path)):
            continue
        manifest = Path(location)
        if not manifest.is_absolute() or manifest.name != "manifest.json" or ".." in manifest.parts:
            continue
        extension = manifest.parent
        root = extension.parent
        if root.name != "Claude Extensions":
            continue
        try:
            if manifest.resolve(strict=True) != manifest or extension.resolve(strict=True) != extension:
                continue
            if root.resolve(strict=True) != root or not manifest.is_file():
                continue
        except (OSError, RuntimeError):
            continue
        directories.add(extension)
    return next(iter(directories)) if len(directories) == 1 else None


def _document_at(root: Path, directory: str, filename: str) -> dict[str, object]:
    """Read one regular JSON file without following links in any component."""
    if Path(directory).name != directory or Path(filename).name != filename:
        raise ValueError("DXT metadata path is not a direct child")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not nofollow:
        raise ValueError("DXT no-follow metadata reads are unavailable")
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("DXT metadata root must be absolute and canonical")
    root_fd = os.open("/", directory_flags)
    try:
        for component in root.parts[1:]:
            child_fd = os.open(component, directory_flags, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = child_fd
        directory_fd = os.open(directory, directory_flags, dir_fd=root_fd)
        try:
            file_fd = os.open(filename, os.O_RDONLY | nofollow | os.O_NONBLOCK, dir_fd=directory_fd)
            with os.fdopen(file_fd, "rb") as raw:
                info = os.fstat(raw.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("DXT metadata is not a private regular file")
                with io.TextIOWrapper(raw, encoding="utf-8") as stream:
                    value: object = json.load(stream)
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)
    if not isinstance(value, dict):
        raise ValueError("DXT metadata must be an object")
    return value


def _roots(
    root: Path, extension: Path, config: ServerConfig, input_paths: list[Path] | None
) -> tuple[str, ...]:
    placeholder = "${user_config.allowed_directories}"
    if placeholder not in config.args:
        return ()
    settings_root = root.parent / "Claude Extensions Settings"
    settings = settings_root / f"{extension.name}.json"
    if input_paths is not None:
        input_paths.append(settings)
    try:
        if not os.path.lexists(settings_root):
            return ()
        if not settings_root.is_dir() or settings_root.resolve(strict=True) != settings_root:
            raise ValueError("DXT settings directory is unavailable")
        if not os.path.lexists(settings):
            return ()
        if settings.is_symlink():
            raise ValueError("DXT settings file is a symbolic link")
        document = _document_at(root.parent, settings_root.name, settings.name)
    except FileNotFoundError:
        return ()
    user_config = document.get("userConfig")
    allowed = user_config.get("allowed_directories") if isinstance(user_config, dict) else None
    if allowed is None:
        return ()
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        raise ValueError("DXT allowed_directories must be a list")
    return tuple(dict.fromkeys(allowed))


def manifest_surface(
    config: ServerConfig,
    dxt_dir: Path | None,
    extension: Path | None = None,
    input_paths: list[Path] | None = None,
) -> tuple[ServerSurface | None, tuple[str, ...], str | None]:
    """Resolve a manifest only when its declared command and args exactly match."""
    dxt_placeholders = {"${__dirname}", "${user_config.allowed_directories}"}
    has_placeholder = any(any(token in argument for token in dxt_placeholders) for argument in config.args)
    if extension is None and not has_placeholder:
        return None, (), None
    if dxt_dir is None:
        if extension is None:
            return None, (), None
        dxt_dir = extension.parent
    try:
        root = dxt_dir.absolute()
        if root.resolve(strict=True) != root or root.name != "Claude Extensions":
            raise ValueError("DXT directory must be the Claude Extensions directory")
        if extension is not None:
            directory = extension.absolute()
            if directory.parent != root or directory.resolve(strict=True) != directory:
                raise ValueError("DXT extension must be a direct child of the selected directory")
            candidates = [directory]
        else:
            candidates = sorted(
                (path for path in root.iterdir() if path.is_dir() and not path.is_symlink()),
                key=lambda path: path.name,
            )
        matches: list[tuple[Path, dict[str, object]]] = []
        for directory in candidates:
            manifest = directory / "manifest.json"
            if manifest.is_symlink():
                raise ValueError("DXT manifest is a symbolic link")
            if not manifest.is_file():
                continue
            if directory.parent != root or directory.resolve(strict=True) != directory:
                raise ValueError("DXT extension escaped selected directory")
            if input_paths is not None:
                input_paths.append(manifest)
            document = _document_at(root, directory.name, manifest.name)
            server = document.get("server")
            launch = server.get("mcp_config") if isinstance(server, dict) else None
            if not isinstance(launch, dict):
                continue
            args = launch.get("args")
            if (
                bool(config.command)
                and launch.get("command") == config.command
                and isinstance(args, list)
                and all(isinstance(item, str) for item in args)
                and args == config.args
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
        roots_reason = None
        try:
            roots = _roots(root, directory, config, input_paths)
        except (OSError, UnicodeError, ValueError) as exc:
            roots = ()
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
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        return None, (), f"DXT metadata unavailable or invalid ({type(exc).__name__})"
