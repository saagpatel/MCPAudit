"""Resolve explicit configuration metadata and form cross-server candidates."""

import tomllib
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from pydantic import TypeAdapter, ValidationError

from mcp_audit.api import parse_config as parse_mcp_config
from mcp_audit.discovery.base import ConfigParseError
from mcp_audit.models import PinVerificationState, ServerConfig, TransportType
from mcp_audit.pinning import PinStore
from redteam.catalog import CATALOG, CATALOG_FILES, catalog_surface, load_catalog
from redteam.chains.dxt import manifest_surface
from redteam.chains.labeler import ToolLabel, label_server
from redteam.chains.templates import TEMPLATES, Template
from redteam.surface import ServerSurface, SurfaceAnnotations, SurfaceConfig, SurfaceTool


class AmbiguousInput(ValueError):
    """A fixed, value-free diagnostic for ambiguous input mappings."""


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
    parse_error: bool = False

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

    def satisfies_template(self) -> bool:
        """Revalidate both roles against current metadata, not cached labels."""
        if self.writer.name == self.executor.name:
            return False
        expected = next((item for item in TEMPLATES if item.name == self.template.name), self.template)
        if (self.template.writer_tag, self.template.executor_tag) != (
            expected.writer_tag,
            expected.executor_tag,
        ):
            return False
        for server, selected, capability, tag in (
            (self.writer, self.writer_label, "write", expected.writer_tag),
            (self.executor, self.executor_label, "execute", expected.executor_tag),
        ):
            if server.surface is None or selected.capability != capability or selected.tag != tag:
                return False
            if not any(
                label.tool == selected.tool and label.capability == capability and label.tag == tag
                for label in label_server(server.surface)
            ):
                return False
        return True

    @property
    def artifact(self) -> str:
        return self.template.artifact

    @property
    def trigger(self) -> str:
        return self.template.trigger

    @property
    def preconditions(self) -> tuple[str, ...]:
        return self.template.preconditions


def _read_configs(path: Path, errors: list[ConfigParseError]) -> list[ServerConfig]:
    if path.name.startswith(".env") or path.suffix not in {".json", ".toml"}:
        raise ValueError("config must be an explicit JSON or TOML file")
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            return parse_mcp_config(content, source=path.name, parse_errors=errors)
        document = tomllib.loads(content)
        server_map = document.get("mcp_servers")
        if not isinstance(server_map, dict):
            raise ValueError("Codex TOML must contain [mcp_servers.*] tables")
        return parse_mcp_config({"mcpServers": server_map}, source=path.name, parse_errors=errors)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"could not parse explicit config ({type(exc).__name__})") from exc


def _pin_surface(pins_dir: Path, config: ServerConfig) -> tuple[ServerSurface | None, bool]:
    """Return a launch-identity-matched usable pin surface and withheld state."""
    path = pins_dir / ".mcp-audit-pins.yaml"
    store = PinStore(
        path=path,
        signing_key=pins_dir / "signing-key.pem",
        trusted_keys_path=pins_dir / "trusted-keys.yaml",
        record_verification=False,
    )
    if store.read_error is not None:
        return None, True
    # Verification also checks persisted signing expectations and the manifest
    # for names that no longer occur in the pin file (or a missing pin file).
    if not store.baseline_trusted(config.name):
        return None, True
    identity_fields = ("command", "args", "transport", "env_keys", "headers_keys")
    candidate_names = sorted(store.pinned_servers())
    withheld_match = False
    matches: list[ServerSurface] = []
    for name in candidate_names:
        verification = store.verification(name)
        if verification is None or verification.state not in {
            PinVerificationState.VERIFIED,
            PinVerificationState.RETIRED_KEY,
        }:
            # A failed signature cannot establish even an alias's identity.
            # Do not use editable launch fields to rule out a matching pin.
            withheld_match = True
            continue
        # A None snapshot cannot establish launch identity and therefore cannot
        # supply tools; report UNKNOWN rather than trusting a same-name catalog row.
        baseline_config: dict[str, object] | None = store.baseline_config(name)
        if baseline_config is None:
            withheld_match = True
            continue
        current = {
            "command": config.command,
            "args": list(config.args),
            "transport": config.transport.value,
            "env_keys": sorted(config.env_keys),
            "headers_keys": sorted(config.headers_keys),
        }
        baseline_url = baseline_config.get("url")
        if config.transport == TransportType.STDIO:
            url_matches = baseline_url == config.url
        else:
            # A redacted snapshot has no private value left to compare. Never
            # treat its placeholder as evidence of a credential/query match.
            endpoint = (
                _url_identity(baseline_url, pin_snapshot=True) if isinstance(baseline_url, str) else None
            )
            url_matches = endpoint is not None and endpoint == _url_identity(config.url)
        if not url_matches or any(baseline_config.get(field) != current[field] for field in identity_fields):
            if name == config.name:
                withheld_match = True
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


def _url_identity(
    url: str | None, *, pin_snapshot: bool = False
) -> tuple[str, str, int, str, tuple[tuple[str, str], ...]] | None:
    """Private HTTP identity; never serialize this comparison key.

    Scheme/host are case-insensitive and absent ports use the scheme default.
    Empty path means `/`; other paths remain exact (case, escapes, dot segments,
    repeated and trailing slashes). Fragments and userinfo are not routing
    identity. Form-decoded query pairs compare in order, preserving blanks,
    duplicates and key/value case. Hash every value, including credentials.
    Pin snapshots cannot establish identity from redacted routing fields.
    Reject whitespace/control characters rather than letting urlsplit strip them.
    """
    if not url or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url):
        return None
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
        if pin_snapshot and "<redacted>" in unquote(parsed.path + "?" + parsed.query):
            return None
        query = tuple(
            (key, sha256(value.encode("utf-8")).hexdigest())
            for key, value in parse_qsl(parsed.query, keep_blank_values=True, errors="strict")
        )
    except (ValueError, UnicodeError):
        return None
    if scheme not in {"http", "https"} or not host:
        return None
    return (
        scheme,
        host.lower(),
        port if port is not None else (443 if scheme == "https" else 80),
        (parsed.path or "/"),
        query,
    )


def _explicit_surface_matches(surface: ServerSurface, name: str, config: ServerConfig) -> bool:
    """Require the mapped name and the identity fields for its transport."""
    declared = surface.config
    if (
        surface.server_name != name
        or declared.transport != config.transport.value
        or declared.env_keys != sorted(config.env_keys)
    ):
        return False
    if config.transport == TransportType.STDIO:
        return (
            bool(declared.command)
            and {"command", "args"} <= declared.model_fields_set
            and declared.command == config.command
            and declared.args == config.args
            and declared.url == config.url
        )
    endpoint = _url_identity(declared.url)
    return (
        {"transport", "url"} <= declared.model_fields_set
        and endpoint is not None
        and endpoint == _url_identity(config.url)
    )


def resolve_configs(
    configs: list[ServerConfig],
    explicit_surfaces: dict[str, ServerSurface] | None = None,
    pins_dir: Path | None = None,
    provenance: dict[str, tuple[str | None, str | None]] | None = None,
    *,
    dxt_dir: Path | None = None,
    extensions: dict[str, Path] | None = None,
    input_paths: list[Path] | None = None,
) -> list[ConfiguredServer]:
    """Resolve explicit metadata, selected pins, DXT manifests, then catalog."""
    explicit = explicit_surfaces or {}
    if input_paths is not None:
        input_paths.extend(CATALOG / name for name in CATALOG_FILES.values())
        if pins_dir is not None:
            input_paths.extend(
                pins_dir / name for name in (".mcp-audit-pins.yaml", "signing-key.pem", "trusted-keys.yaml")
            )
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
        if mapped_surface is None and pins_dir is not None:
            surface, pin_withheld = _pin_surface(pins_dir, config)
            if surface is not None:
                source = "pin"
        if (
            mapped_surface is None
            and surface is None
            and not pin_withheld
            and config.transport == TransportType.STDIO
        ):
            surface, dxt_roots, dxt_reason = manifest_surface(
                config, dxt_dir, (extensions or {}).get(name), input_paths=input_paths
            )
            reason = "; ".join(part for part in (reason, dxt_reason) if part) or None
            if surface is not None:
                source, roots = "dxt-manifest", dxt_roots
            elif dxt_reason is None:
                surface, catalog_reason = catalog_surface(config, catalog)
                reason = "; ".join(part for part in (reason, catalog_reason) if part) or None
                if surface is not None:
                    source = "catalog"
        if surface is not None:
            # All sources must expose the same verified launch identity to the
            # labeler, even when the configured name is an arbitrary alias.
            surface = surface.model_copy(
                update={
                    "server_name": name,
                    "config": SurfaceConfig(
                        command=config.command,
                        args=list(config.args),
                        transport=config.transport.value,
                        url=config.url,
                        env_keys=sorted(config.env_keys),
                    ),
                }
            )
        provenance_source, provenance_location = (provenance or {}).get(name, (None, None))
        result.append(
            ConfiguredServer(
                name,
                surface,
                roots,
                reason
                if surface
                else (
                    "; ".join(
                        part
                        for part in (
                            reason,
                            "Matching pin baseline was withheld or lacked verifiable launch identity",
                        )
                        if part
                    )
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
    input_paths: list[Path] | None = None,
    *,
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
            if input_paths is not None:
                input_paths.append(target)
            explicit[name] = ServerSurface.load(target)
    errors: list[ConfigParseError] = []
    configs = _read_configs(path, errors)
    if len({config.name for config in configs}) != len(configs):
        raise AmbiguousInput("duplicate server names across config maps are ambiguous")
    unused = set(explicit) - {config.name for config in configs} - {error.server_name for error in errors}
    if unused:
        raise AmbiguousInput("surfaces mapping contains an unknown server name")
    resolved = resolve_configs(configs, explicit, pins_dir, dxt_dir=dxt_dir, input_paths=input_paths)
    resolved.extend(
        ConfiguredServer(
            error.server_name or "<unknown entry>",
            None,
            reason=(
                "Malformed server entry (ConfigParseError)"
                if error.finding_type == "malformed_server_entry"
                else "Config parse issue (ConfigParseError)"
            ),
            parse_error=True,
        )
        for error in errors
    )
    return resolved


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
