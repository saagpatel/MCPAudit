"""Resolve explicit configuration metadata and form cross-server candidates."""

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from redteam.catalog import load_catalog
from redteam.chains.labeler import ToolLabel, label_server
from redteam.chains.templates import TEMPLATES, Template
from redteam.surface import ServerSurface


class _Entry(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    command: str | None = None
    args: list[str] = Field(default_factory=list)


class _Config(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    mcpServers: dict[str, _Entry]


@dataclass(frozen=True)
class ConfiguredServer:
    name: str
    surface: ServerSurface | None
    roots: tuple[str, ...] = ()
    reason: str | None = None

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


def load_config(path: Path, surfaces_file: Path | None = None) -> list[ConfiguredServer]:
    """Read an explicit config and optional adjacent name-to-surface-filename mapping."""
    if path.suffix != ".json" or path.name.startswith(".env"):
        raise ValueError("config must be an explicit JSON file")
    config = _Config.model_validate_json(path.read_text(encoding="utf-8"))
    explicit: dict[str, str] = {}
    if surfaces_file is not None:
        if (
            surfaces_file.suffix != ".json"
            or surfaces_file.name.startswith(".env")
            or surfaces_file.resolve().parent != path.resolve().parent
        ):
            raise ValueError("surfaces file must be adjacent to config")
        explicit = TypeAdapter(dict[str, str]).validate_json(
            surfaces_file.read_text(encoding="utf-8"), strict=True
        )
    catalog = load_catalog()
    result: list[ConfiguredServer] = []
    for name, entry in sorted(config.mcpServers.items()):
        args = entry.args
        command = entry.command
        identity = None
        roots: tuple[str, ...] = ()
        if command == "uvx" and args and args[0] == "mcp-server-git":
            identity = "pypi:mcp-server-git"
            if len(args) == 3 and args[1] in ("--repository", "-r"):
                roots = (args[2],)
        elif (
            command == "npx"
            and len(args) >= 2
            and args[:2] == ["-y", "@modelcontextprotocol/server-filesystem"]
        ):
            identity = "npm:@modelcontextprotocol/server-filesystem"
            if all(isinstance(root, str) and not root.startswith("-") for root in args[2:]):
                roots = tuple(args[2:])
        surface = None
        if name in explicit:
            filename = explicit[name]
            surface_path = path.parent / filename
            if (
                Path(filename).name != filename
                or not filename.endswith(".json")
                or filename.startswith(".env")
                or surface_path.resolve().parent != path.resolve().parent
            ):
                raise ValueError("surface must be a filename adjacent to config")
            surface = ServerSurface.load(surface_path)
        elif identity:
            surface = catalog[identity]
        if surface is not None:
            surface = surface.model_copy(update={"server_name": name})
        result.append(
            ConfiguredServer(name, surface, roots, None if surface else "No explicit or catalog surface")
        )
    return result


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
