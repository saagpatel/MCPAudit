"""Resolve explicit configuration metadata and form cross-server candidates."""

import tomllib
from dataclasses import dataclass
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from mcp_audit.api import parse_config as parse_mcp_config
from mcp_audit.models import PinVerificationState, ServerConfig
from mcp_audit.pinning import PinStore
from redteam.catalog import catalog_surface, load_catalog
from redteam.chains.dxt import manifest_surface
from redteam.chains.labeler import ToolLabel, label_server
from redteam.chains.templates import TEMPLATES, Template
from redteam.surface import ServerSurface, SurfaceAnnotations, SurfaceTool


@dataclass(frozen=True)
class ConfiguredServer:
    name: str
    surface: ServerSurface | None
    roots: tuple[str, ...] = ()
    reason: str | None = None
    env_keys: tuple[str, ...] = ()
    source: str = "unknown"
    provenance_source: str | None = None
    provenance_location: str | None = None

    @property
    def tool_surface(self) -> str:
        return "KNOWN" if self.surface is not None else "UNKNOWN"


@dataclass(frozen=True)
class Step:
    server: str
    tool: str
    action: str


@dataclass(frozen=True)
class CandidateChain:
    template: Template
    steps: tuple[Step, ...]
    writer: ConfiguredServer
    executor: ConfiguredServer
    writer_label: ToolLabel
    executor_label: ToolLabel

    @property
    def artifact(self) -> str:
        return self.template.artifact

    @property
    def trigger(self) -> str:
        return self.template.trigger

    @property
    def preconditions(self) -> tuple[str, ...]:
        return self.template.preconditions


def _read_configs(path: Path) -> list[ServerConfig]:
    if path.name.startswith(".env") or path.suffix not in {".json", ".toml"}:
        raise ValueError("config must be an explicit JSON or TOML file")
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            return parse_mcp_config(content, source=path.name)
        document = tomllib.loads(content)
        server_map = document.get("mcp_servers")
        if not isinstance(server_map, dict):
            raise ValueError("Codex TOML must contain [mcp_servers.*] tables")
        return parse_mcp_config({"mcpServers": server_map}, source=path.name)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"could not parse explicit config ({type(exc).__name__})") from exc


def _pin_surface(pins_dir: Path, config: ServerConfig) -> tuple[ServerSurface | None, bool]:
    """Return a launch-identity-matched usable pin surface and withheld state."""
    path = pins_dir / ".mcp-audit-pins.yaml"
    if not path.is_file():
        return None, False
    store = PinStore(
        path=path,
        signing_key=pins_dir / "signing-key.pem",
        trusted_keys_path=pins_dir / "trusted-keys.yaml",
        record_verification=False,
    )
    if store.read_error is not None:
        return None, True
    identity_fields = ("command", "args", "url", "transport", "env_keys", "headers_keys")
    candidate_names = sorted(store.pinned_servers())
    withheld_match = False
    matches: list[ServerSurface] = []
    for name in candidate_names:
        verification = store.verification(name)
        if verification is None or verification.state not in {
            PinVerificationState.VERIFIED,
            PinVerificationState.RETIRED_KEY,
        }:
            if name == config.name:
                withheld_match = True
            continue
        # A None snapshot cannot establish launch identity and therefore cannot
        # supply tools; report UNKNOWN rather than trusting a same-name catalog row.
        baseline_config = store.baseline_config(name)
        if baseline_config is None:
            if name == config.name:
                withheld_match = True
            continue
        current = {
            "command": config.command,
            "args": list(config.args),
            "url": config.url,
            "transport": config.transport.value,
            "env_keys": sorted(config.env_keys),
            "headers_keys": sorted(config.headers_keys),
        }
        if any(baseline_config.get(field) != current[field] for field in identity_fields):
            continue
        tools = store.baseline_tools(name)
        if not tools:
            withheld_match = True
            continue
        matches.append(
            ServerSurface(
                server_name=config.name,
                tools=[
                    SurfaceTool(
                        name=tool.name,
                        description=tool.description,
                        input_schema=tool.input_schema or {},
                        annotations=(
                            SurfaceAnnotations.model_validate(
                                tool.annotations.model_dump(exclude_none=True), strict=True
                            )
                            if tool.annotations is not None
                            else None
                        ),
                        title=tool.title,
                    )
                    for tool in tools
                ],
                source="pin",
                provenance=(
                    "signature-verified historical pin matching launch identity; current surface unverified"
                ),
            )
        )
    if withheld_match:
        return None, True
    if matches:
        first = matches[0]
        signature = first.model_dump(mode="json", exclude_none=True)
        if any(match.model_dump(mode="json", exclude_none=True) != signature for match in matches[1:]):
            return None, True
        return first, False
    return None, withheld_match


def _explicit_surface_matches(surface: ServerSurface, name: str, config: ServerConfig) -> bool:
    """Require mapped surface name and any declared launch fields to match."""
    if surface.server_name != name:
        return False
    configured: dict[str, object] = {
        "command": config.command,
        "args": list(config.args),
        "transport": config.transport.value,
        "url": config.url,
        "env_keys": sorted(config.env_keys),
    }
    has_launch_identity = any(
        (
            surface.config.command is not None,
            bool(surface.config.args),
            surface.config.transport != "stdio",
            surface.config.url is not None,
            bool(surface.config.env_keys),
        )
    )
    if not has_launch_identity:
        return True
    return all(getattr(surface.config, field) == configured[field] for field in configured)


def resolve_configs(
    configs: list[ServerConfig],
    explicit_surfaces: dict[str, ServerSurface] | None = None,
    pins_dir: Path | None = None,
    dxt_dir: Path | None = None,
    extensions: dict[str, Path] | None = None,
    provenance: dict[str, tuple[str | None, str | None]] | None = None,
) -> list[ConfiguredServer]:
    """Resolve explicit metadata, selected pins, DXT manifests, then catalog."""
    explicit = explicit_surfaces or {}
    catalog = load_catalog()
    result: list[ConfiguredServer] = []
    for config in sorted(configs, key=lambda server: server.name):
        name = config.name
        args = config.args
        command = config.command
        roots: tuple[str, ...] = ()
        if command == "uvx" and args and args[0] == "mcp-server-git":
            if len(args) == 3 and args[1] in ("--repository", "-r"):
                roots = (args[2],)
        elif (
            command == "npx"
            and len(args) >= 2
            and args[:2] == ["-y", "@modelcontextprotocol/server-filesystem"]
        ):
            if all(isinstance(root, str) and not root.startswith("-") for root in args[2:]):
                roots = tuple(args[2:])
        mapped_surface = explicit.get(name)
        surface = (
            mapped_surface
            if mapped_surface is not None and _explicit_surface_matches(mapped_surface, name, config)
            else None
        )
        source = "explicit" if surface is not None else "unknown"
        pin_withheld = False
        reason = (
            "Explicit surface name or declared launch identity did not match configured server"
            if mapped_surface is not None and surface is None
            else None
        )
        if surface is None and pins_dir is not None:
            surface, pin_withheld = _pin_surface(pins_dir, config)
            if surface is not None:
                source = "pin"
        if surface is None and not pin_withheld:
            surface, dxt_roots, reason = manifest_surface(config, dxt_dir, (extensions or {}).get(name))
            if surface is not None:
                source, roots = "dxt-manifest", dxt_roots
            elif reason is None:
                surface, reason = catalog_surface(config, catalog)
                if surface is not None:
                    source = "catalog"
        if surface is not None:
            surface = surface.model_copy(update={"server_name": name})
        provenance_source, provenance_location = (provenance or {}).get(name, (None, None))
        result.append(
            ConfiguredServer(
                name,
                surface,
                roots,
                reason
                if surface
                else (
                    "Matching pin baseline was withheld or lacked verifiable launch identity"
                    if pin_withheld
                    else reason or "No explicit, pin, DXT manifest, or catalog surface"
                ),
                tuple(sorted(config.env_keys)),
                source,
                provenance_source=provenance_source,
                provenance_location=provenance_location,
            )
        )
    return result


def load_config(
    path: Path,
    surfaces_file: Path | None = None,
    pins_dir: Path | None = None,
    dxt_dir: Path | None = None,
) -> list[ConfiguredServer]:
    """Read an explicit JSON/Codex TOML config and optional explicit surfaces file."""
    explicit: dict[str, ServerSurface] = {}
    if surfaces_file is not None:
        if (
            surfaces_file.suffix != ".json"
            or surfaces_file.name.startswith(".env")
            or surfaces_file.resolve().parent != path.resolve().parent
        ):
            raise ValueError("surfaces file must be adjacent to config")
        try:
            mapping = TypeAdapter(dict[str, str]).validate_json(
                surfaces_file.read_text(encoding="utf-8"), strict=True
            )
        except (OSError, UnicodeError, ValidationError) as exc:
            raise ValueError("surfaces mapping must be a JSON object of server names to filenames") from exc
        for name, filename in mapping.items():
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or not filename.endswith(".json")
                or filename.startswith(".env")
            ):
                raise ValueError("surface must be a filename adjacent to config")
            target = path.parent / filename
            if target.resolve().parent != path.resolve().parent:
                raise ValueError("surface must be a filename adjacent to config")
            explicit[name] = ServerSurface.load(target)
    return resolve_configs(_read_configs(path), explicit, pins_dir, dxt_dir)


def pair_servers(
    servers: list[ConfiguredServer], templates: tuple[Template, ...] | None = None
) -> list[CandidateChain]:
    labels = [
        (server, label)
        for server in servers
        if server.surface is not None
        for label in label_server(server.surface)
    ]
    writers = [(server, label) for server, label in labels if label.capability == "write"]
    executors = [(server, label) for server, label in labels if label.capability == "execute"]
    return [
        CandidateChain(
            template,
            tuple(
                Step(writer.name, wlabel.tool, action)
                for action in (template.writer_actions or (template.artifact,))
            )
            + (Step(executor.name, elabel.tool, template.trigger),),
            writer,
            executor,
            wlabel,
            elabel,
        )
        for writer, wlabel in writers
        for executor, elabel in executors
        if writer.name != executor.name
        for template in (templates if templates is not None else TEMPLATES)
        if wlabel.tag == template.writer_tag and elabel.tag == template.executor_tag
    ]
