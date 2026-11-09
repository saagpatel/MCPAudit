"""Canonical inert server metadata and a deliberately restricted AST extractor.

Extraction describes declared metadata, never runtime behavior. Function bodies
are not evaluated. Unknown metadata forms fail closed rather than disappearing.
The AST launch config is synthetic (``python server.py``), not a resolved command.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError

from mcp_audit.models import (
    ClientType,
    ResourceInfo,
    ServerConfig,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)


class SurfaceConfig(_Model):
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    transport: Literal["stdio", "http", "sse"] = "stdio"
    url: str | None = None
    env_keys: list[str] = Field(default_factory=list)


class SurfaceAnnotations(_Model):
    title: str | None = None
    read_only_hint: bool | None = Field(
        default=None, validation_alias=AliasChoices("read_only_hint", "readOnlyHint")
    )
    destructive_hint: bool | None = Field(
        default=None, validation_alias=AliasChoices("destructive_hint", "destructiveHint")
    )
    idempotent_hint: bool | None = Field(
        default=None, validation_alias=AliasChoices("idempotent_hint", "idempotentHint")
    )
    open_world_hint: bool | None = Field(
        default=None, validation_alias=AliasChoices("open_world_hint", "openWorldHint")
    )


class SurfaceTool(_Model):
    name: str
    description: str | None = None
    input_schema: dict[str, object] = Field(
        default_factory=dict, validation_alias=AliasChoices("input_schema", "inputSchema")
    )
    annotations: SurfaceAnnotations | None = None
    title: str | None = None


class SurfaceResource(_Model):
    uri: str
    name: str | None = None
    description: str | None = None


class ServerSurface(_Model):
    server_name: str
    config: SurfaceConfig = Field(default_factory=SurfaceConfig)
    tools: list[SurfaceTool] = Field(default_factory=list)
    resources: list[SurfaceResource] = Field(default_factory=list)
    source: Literal["fixture", "ast", "catalog", "pin"]
    provenance: str | None = None

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> ServerSurface:
        return cls.model_validate_json(text)

    @classmethod
    def load(cls, path: Path) -> ServerSurface:
        return cls.from_json(path.read_text(encoding="utf-8"))

    def to_config(self) -> ServerConfig:
        return ServerConfig(
            name=self.server_name,
            client=ClientType.CLAUDE_CODE,
            config_path="redteam/surface.json",
            command=self.config.command,
            args=list(self.config.args),
            transport=TransportType(self.config.transport),
            url=self.config.url,
            env_keys=sorted(set(self.config.env_keys)),
        )

    def to_tools(self) -> list[ToolInfo]:
        return [
            ToolInfo(
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema,
                title=tool.title,
                annotations=(
                    ToolAnnotations.model_validate(tool.annotations.model_dump())
                    if tool.annotations
                    else None
                ),
            )
            for tool in self.tools
        ]

    def to_resources(self) -> list[ResourceInfo]:
        return [ResourceInfo(**resource.model_dump()) for resource in self.resources]


class Unknown(_Model):
    status: Literal["UNKNOWN"] = "UNKNOWN"
    reason: str


class _Unsupported(ValueError):
    """An explicit boundary of the restricted extractor."""


def _literal(node: ast.expr) -> object:
    # literal_eval alone also accepts forms such as set(). Keep the grammar
    # explicit: no calls, unpacking, operators with user operands, or bindings.
    if isinstance(node, ast.Constant) and (node.value is None or type(node.value) in (str, bool, int, float)):
        return node.value
    if isinstance(node, ast.List):
        return [_literal(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        for key, child in zip(node.keys, node.values, strict=True):
            if key is None:
                raise _Unsupported("metadata dictionary unpacking is unsupported")
            _literal(key)
            _literal(child)
    elif not (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) in (int, float)
    ):
        raise _Unsupported("metadata must use inert literal forms")
    try:
        value: object = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError) as exc:
        raise _Unsupported("metadata must be literal") from exc
    return value


_ANNOTATION_NAMES = {"str", "int", "float", "bool", "bytes", "object", "dict", "list"}


def _annotation(node: ast.expr) -> None:
    """Accept only known builtin types, including inert forward references."""
    if isinstance(node, ast.Name) and node.id in _ANNOTATION_NAMES:
        return
    if isinstance(node, ast.Constant):
        if node.value is None:
            return
        if isinstance(node.value, str):
            # FastMCP may resolve string annotations later. Validate their
            # contents too, without evaluating a forward reference.
            _annotation(ast.parse(node.value, mode="eval", feature_version=(3, 11)).body)
            return
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id == "list" and not isinstance(node.slice, ast.Tuple):
            _annotation(node.slice)
            return
        if node.value.id == "dict" and isinstance(node.slice, ast.Tuple) and len(node.slice.elts) == 2:
            for item in node.slice.elts:
                _annotation(item)
            return
    raise _Unsupported("annotations must use inert known type forms")


def _is_attr(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "mcp"
        and node.attr == name
    )


def _schema(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, object]:
    args = node.args
    if args.vararg or args.kwarg or args.posonlyargs:
        raise _Unsupported("variadic and positional-only parameters are unsupported")
    params = [*args.args, *args.kwonlyargs]
    defaults: list[ast.expr | None] = (
        [None] * (len(args.args) - len(args.defaults)) + list(args.defaults) + list(args.kw_defaults)
    )
    types = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}
    properties: dict[str, object] = {}
    required: list[str] = []
    for param, default in zip(params, defaults, strict=True):
        if param.annotation is not None:
            _annotation(param.annotation)
        if not isinstance(param.annotation, ast.Name) or param.annotation.id not in types:
            raise _Unsupported(f"parameter {param.arg}: only str/int/float/bool annotations are supported")
        kind = param.annotation.id
        entry: dict[str, object] = {"type": types[kind]}
        if default is None:
            required.append(param.arg)
        else:
            value = _literal(default)
            valid = (
                (kind == "str" and isinstance(value, str))
                or (kind == "bool" and isinstance(value, bool))
                or (kind == "int" and type(value) is int)
                or (kind == "float" and type(value) in (int, float))
            )
            if not valid:
                raise _Unsupported(f"parameter {param.arg}: default does not match primitive type")
            entry["default"] = value
        properties[param.arg] = entry
    return {"type": "object", "properties": properties, "required": required}


def _tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> SurfaceTool:
    if node.name in _ANNOTATION_NAMES:
        raise _Unsupported("tool declarations must not rebind known annotation types")
    if node.returns is not None:
        _annotation(node.returns)
    if len(node.decorator_list) != 1:
        raise _Unsupported("tools must have exactly one @mcp.tool decorator")
    decorator = node.decorator_list[0]
    kwargs: dict[str, object] = {}
    if isinstance(decorator, ast.Call) and _is_attr(decorator.func, "tool"):
        if decorator.args:
            raise _Unsupported("positional tool decorator arguments are unsupported")
        for kw in decorator.keywords:
            if kw.arg not in {"name", "description", "annotations"} or kw.arg in kwargs:
                raise _Unsupported("unsupported or duplicate tool decorator keyword")
            kwargs[kw.arg] = _literal(kw.value)
        if "annotations" in kwargs and not isinstance(kwargs["annotations"], dict):
            raise _Unsupported("tool annotations must be a literal dictionary")
    elif not _is_attr(decorator, "tool"):
        raise _Unsupported("only @mcp.tool exports are supported")
    return SurfaceTool.model_validate(
        {
            "name": kwargs.get("name", node.name),
            "description": kwargs.get("description", ast.get_docstring(node)),
            "input_schema": _schema(node),
            "annotations": kwargs.get("annotations"),
        }
    )


def _main_transport(node: ast.If) -> Literal["stdio", "http", "sse"]:
    # Only the scaffold's literal __main__ guard is accepted, and never executed.
    if (
        not isinstance(node.test, ast.Compare)
        or not isinstance(node.test.left, ast.Name)
        or node.test.left.id != "__name__"
        or len(node.test.ops) != 1
        or not isinstance(node.test.ops[0], ast.Eq)
        or len(node.test.comparators) != 1
        or not isinstance(node.test.comparators[0], ast.Constant)
        or node.test.comparators[0].value != "__main__"
        or node.orelse
        or len(node.body) != 1
        or not isinstance(node.body[0], ast.Expr)
        or not isinstance(node.body[0].value, ast.Call)
    ):
        raise _Unsupported("unsupported module-level control flow")
    call = node.body[0].value
    if not _is_attr(call.func, "run") or call.args or len(call.keywords) != 1:
        raise _Unsupported("only literal mcp.run(transport=...) is supported in the main guard")
    kw = call.keywords[0]
    transport = _literal(kw.value)
    if kw.arg != "transport" or transport not in ("stdio", "http", "sse"):
        raise _Unsupported("unsupported transport")
    if transport == "stdio":
        return "stdio"
    if transport == "http":
        return "http"
    return "sse"


def extract_from_source(path: Path) -> ServerSurface | Unknown:
    """Parse inert text only; unsupported declarations return a reasoned UNKNOWN."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 11))
        name: str | None = None
        tools: list[SurfaceTool] = []
        transport: Literal["stdio", "http", "sse"] = "stdio"
        has_main = False
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                if not isinstance(node.value.value, str):
                    raise _Unsupported("unsupported module expression")
            elif isinstance(node, ast.ImportFrom):
                if node.level or not (
                    (
                        node.module == "fastmcp"
                        and [(n.name, n.asname) for n in node.names] == [("FastMCP", None)]
                    )
                    or (
                        node.module == "__future__"
                        and [(n.name, n.asname) for n in node.names] == [("annotations", None)]
                    )
                ):
                    raise _Unsupported("unsupported import form")
            elif isinstance(node, ast.Assign):
                if (
                    name is not None
                    or len(node.targets) != 1
                    or not isinstance(node.targets[0], ast.Name)
                    or node.targets[0].id != "mcp"
                    or not isinstance(node.value, ast.Call)
                    or not isinstance(node.value.func, ast.Name)
                    or node.value.func.id != "FastMCP"
                    or len(node.value.args) != 1
                    or node.value.keywords
                ):
                    raise _Unsupported("expected a single mcp = FastMCP(literal_name) declaration")
                value = _literal(node.value.args[0])
                if not isinstance(value, str) or not value:
                    raise _Unsupported("server name must be a nonempty literal string")
                name = value
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if name is None or has_main or node.name in {"mcp", "FastMCP"}:
                    raise _Unsupported("tool declaration outside the supported module order")
                tool = _tool(node)
                if any(existing.name == tool.name for existing in tools):
                    raise _Unsupported("duplicate tool name")
                tools.append(tool)
            elif isinstance(node, ast.If) and name is not None and not has_main:
                transport = _main_transport(node)
                has_main = True
            else:
                raise _Unsupported(f"unsupported module statement: {type(node).__name__}")
        if name is None:
            raise _Unsupported("missing mcp = FastMCP(literal_name) declaration")
        return ServerSurface(
            server_name=name,
            config=SurfaceConfig(command="python", args=["server.py"], transport=transport),
            tools=tools,
            source="ast",
        )
    except (OSError, UnicodeError, SyntaxError, _Unsupported, ValidationError) as exc:
        # Do not include source text or an absolute caller path in a result.
        if isinstance(exc, _Unsupported):
            reason = str(exc)
        elif isinstance(exc, ValidationError):
            error = exc.errors(include_url=False, include_input=False)[0]
            location = ".".join(str(part) for part in error["loc"])
            reason = f"invalid literal metadata at {location}: {error['type']}"
        elif isinstance(exc, SyntaxError):
            reason = f"invalid Python syntax at line {exc.lineno}"
        else:
            reason = type(exc).__name__
        return Unknown(reason=reason)
