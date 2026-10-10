"""Static, offline checks for tool schema extensions and metadata."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import ParseResult, urlparse

from mcp_audit.models import SchemaFinding, ToolInfo

_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CREDENTIAL_WORDS = {
    "auth",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "key",
    "password",
    "secret",
    "token",
}
_PRIMITIVE_TYPES = {"string", "number", "integer", "boolean"}


def _local_ref(root: dict[str, object], ref: str) -> object | None:
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        return None
    current: object = root
    for part in ref[2:].split("/"):
        token = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(token)
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return None
    return current


def _reachable_nodes(root: dict[str, object]) -> Iterator[dict[str, object]]:
    stack = [root]
    seen: set[int] = set()
    while stack and len(seen) < 2048:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        ref = node.get("$ref")
        if isinstance(ref, str):
            target = _local_ref(root, ref)
            if isinstance(target, dict):
                stack.append(target)
        for key in (
            "properties",
            "items",
            "allOf",
            "anyOf",
            "oneOf",
            "additionalProperties",
            "contains",
            "unevaluatedItems",
            "unevaluatedProperties",
            "prefixItems",
            "dependentSchemas",
            "patternProperties",
            "else",
            "if",
            "not",
            "then",
        ):
            value = node.get(key)
            if isinstance(value, dict):
                stack.extend(child for child in value.values() if isinstance(child, dict))
            elif isinstance(value, list):
                stack.extend(child for child in value if isinstance(child, dict))


def _all_nodes(root: dict[str, object]) -> Iterator[dict[str, object]]:
    stack: list[object] = [root]
    seen: set[int] = set()
    while stack and len(seen) < 2048:
        value = stack.pop()
        if isinstance(value, dict):
            if id(value) in seen:
                continue
            seen.add(id(value))
            yield value
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)


def _origin(parsed: ParseResult) -> tuple[str, str, int | None] | None:
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if not scheme or not isinstance(hostname, str):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, hostname.casefold(), None if port == default_port else port


def _schema_rules(tool: ToolInfo, schema: dict[str, object]) -> list[SchemaFinding]:
    findings: list[SchemaFinding] = []
    reachable = list(_reachable_nodes(schema))
    reachable_ids = {id(node) for node in reachable}
    headers: dict[str, str] = {}
    for node in _all_nodes(schema):
        header = node.get("x-mcp-header")
        if header is None:
            continue
        if id(node) not in reachable_ids:
            findings.append(
                SchemaFinding(
                    tool_name=tool.name,
                    kind="header_unreachable",
                    evidence=["x-mcp-header appears outside a reachable schema branch"],
                )
            )
            continue
        name = str(header)
        if not isinstance(header, str) or not _HEADER_TOKEN.fullmatch(header):
            findings.append(
                SchemaFinding(
                    tool_name=tool.name,
                    kind="header_invalid",
                    evidence=["x-mcp-header must be an RFC token string"],
                )
            )
        elif header.casefold() in headers:
            findings.append(
                SchemaFinding(
                    tool_name=tool.name,
                    kind="header_duplicate",
                    evidence=[f"x-mcp-header duplicates {headers[header.casefold()]}"],
                )
            )
        else:
            headers[header.casefold()] = header
        raw_type = node.get("type")
        types = (
            {raw_type}
            if isinstance(raw_type, str)
            else {value for value in raw_type if isinstance(value, str)}
            if isinstance(raw_type, list)
            else set()
        )
        if not types or not types <= _PRIMITIVE_TYPES:
            findings.append(
                SchemaFinding(
                    tool_name=tool.name,
                    kind="header_type",
                    evidence=["x-mcp-header property must have a primitive type"],
                )
            )
    for node in _all_nodes(schema):
        ref = node.get("$ref")
        if isinstance(ref, str) and not ref.startswith("#"):
            findings.append(
                SchemaFinding(
                    tool_name=tool.name, kind="external_ref", evidence=["schema contains an external $ref"]
                )
            )
    # A credential-looking parameter mapped to a request header duplicates the
    # credential's transport declaration and can make schema consumers disagree.
    for node in reachable:
        properties = node.get("properties")
        if not isinstance(properties, dict):
            continue
        for name, prop in properties.items():
            if not isinstance(name, str) or not isinstance(prop, dict) or "x-mcp-header" not in prop:
                continue
            words = set(re.findall(r"[a-z0-9]+", name.lower()))
            if words & _CREDENTIAL_WORDS:
                findings.append(
                    SchemaFinding(
                        tool_name=tool.name,
                        kind="credential_header",
                        evidence=["credential-looking parameter is mirrored to a header"],
                    )
                )
    return findings


def scan_tool_schema(tool: ToolInfo, *, server_url: str | None = None) -> list[SchemaFinding]:
    """Inspect served schemas and icons without fetching or resolving remote references."""
    findings: list[SchemaFinding] = []
    for schema in (tool.input_schema, tool.output_schema):
        if isinstance(schema, dict):
            findings.extend(_schema_rules(tool, schema))
    try:
        server = urlparse(server_url) if server_url else None
    except ValueError:
        server = None
    for icon in tool.icons or []:
        src = icon.get("src")
        if not isinstance(src, str):
            continue
        try:
            parsed = urlparse(src)
        except ValueError:
            findings.append(
                SchemaFinding(tool_name=tool.name, kind="icon_source", evidence=["icon source is malformed"])
            )
            continue
        if parsed.scheme != "https" and parsed.scheme != "data":
            findings.append(
                SchemaFinding(
                    tool_name=tool.name, kind="icon_source", evidence=["icon source is not HTTPS or data:"]
                )
            )
        elif parsed.scheme == "https" and server:
            icon_origin = _origin(parsed)
            server_origin = _origin(server)
            if server_origin is not None and icon_origin != server_origin:
                findings.append(
                    SchemaFinding(
                        tool_name=tool.name,
                        kind="icon_origin",
                        evidence=["icon source is cross-origin from the MCP endpoint"],
                    )
                )
    return findings
