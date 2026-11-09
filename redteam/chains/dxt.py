"""Read only DXT manifests and their single allowlisted settings key."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.models import ServerConfig
from redteam.surface import ServerSurface, SurfaceTool

MAX_INPUT_BYTES = 1024 * 1024


def read_regular_file(path: Path) -> str:
    """Read bounded UTF-8 input without following links in any path component."""
    path = path.absolute()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise ValueError("no-follow regular-file reads are unavailable")
    directory_flags = os.O_RDONLY | directory | nofollow
    if ".." in path.parts:
        raise ValueError("input path must be canonical")
    directory_fd = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        # Reject FIFOs and links before opening; recheck the opened descriptor
        # below to cover replacements between stat and open. NONBLOCK bounds races.
        info = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("input is not a private regular file")
        if info.st_size > MAX_INPUT_BYTES:
            raise ValueError("input exceeds size cap")
        file_fd = os.open(path.name, os.O_RDONLY | nofollow | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(file_fd, "rb") as raw:
            info = os.fstat(raw.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("input is not a private regular file")
            if info.st_size > MAX_INPUT_BYTES:
                raise ValueError("input exceeds size cap")
            content = raw.read(MAX_INPUT_BYTES + 1)
            if len(content) > MAX_INPUT_BYTES:
                raise ValueError("input exceeds size cap")
    finally:
        os.close(directory_fd)
    return content.decode("utf-8")


@dataclass(frozen=True)
class DxtSpec:
    command: str
    args: list[str]
    env_keys: list[str]
    transport: str = "stdio"
    url: str | None = None


@dataclass(frozen=True)
class DxtSighting:
    name: str
    spec: DxtSpec
    provenance: dict[str, str]


class DxtCollector:
    """Local replacement: never invoke shadow-mcp's unhardened DXT reader."""

    source = "dxt"

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        self.errors: list[str] = []

    def collect(self) -> list[DxtSighting]:
        sightings: list[DxtSighting] = []
        try:
            if not os.path.lexists(self.root):
                return []
            if self.root.resolve(strict=True) != self.root:
                raise ValueError("extension root is a link")
            with os.scandir(self.root) as entries:
                directories = sorted(entries, key=lambda entry: entry.name)
            for entry in directories:
                try:
                    if entry.is_symlink():
                        raise ValueError("extension directory is a link")
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    document = _document_at(self.root, entry.name, "manifest.json")
                    server = document.get("server")
                    launch = server.get("mcp_config") if isinstance(server, dict) else None
                    if not isinstance(launch, dict):
                        raise ValueError("missing nested launch metadata")
                    command = launch.get("command")
                    args = launch.get("args", [])
                    env = launch.get("env", {})
                    name = document.get("name", entry.name)
                    if (
                        not isinstance(name, str)
                        or not name
                        or not isinstance(command, str)
                        or not command
                        or not isinstance(args, list)
                        or any(not isinstance(arg, str) for arg in args)
                        or not isinstance(env, dict)
                        or any(not isinstance(key, str) for key in env)
                        or launch.get("url") is not None
                        or launch.get("transport", launch.get("type", "stdio")) != "stdio"
                    ):
                        raise ValueError("invalid stdio launch metadata")
                    sightings.append(
                        DxtSighting(
                            name,
                            DxtSpec(command, args, sorted(env)),
                            {"source": "dxt", "location": str(self.root / entry.name / "manifest.json")},
                        )
                    )
                except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
                    self.errors.append(f"DXT manifest skipped ({type(exc).__name__})")
        except (OSError, ValueError, RuntimeError) as exc:
            self.errors.append(f"DXT directory skipped ({type(exc).__name__})")
        return sightings


def metadata_inputs(extensions: Path, settings: Path) -> list[Path]:
    """List metadata destinations, including sources that yield no servers.

    Register files as well as directories so aliases outside the directories
    cannot overwrite them. Only enumerate names; do not parse their contents.
    """
    extensions = extensions.absolute()
    manifests: list[Path] = []
    try:
        if extensions.resolve(strict=True) == extensions:
            with os.scandir(extensions) as entries:
                manifests = [
                    extensions / entry.name / "manifest.json"
                    for entry in entries
                    if entry.is_dir(follow_symlinks=False)
                ]
    except (OSError, RuntimeError):
        # Collection reports unavailable directories; protection only lists names.
        pass
    return [*sorted(manifests), *sorted(settings.glob("*.json"))]


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
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("DXT metadata root must be absolute and canonical")
    value: object = json.loads(read_regular_file(root / directory / filename))
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
