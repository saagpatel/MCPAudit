"""Static, offline checks for tool schema extensions and metadata."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import ParseResult, unquote, urlparse

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
_MAX_SCHEMA_NODES = 2048
_SCHEMA_MAP_KEYWORDS = ("properties", "patternProperties", "dependentSchemas", "dependencies")
_SCHEMA_ARRAY_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SINGLE_SCHEMA_KEYWORDS = (
    "items",
    "additionalItems",
    "additionalProperties",
    "contains",
    "unevaluatedItems",
    "unevaluatedProperties",
    "propertyNames",
    "contentSchema",
    "else",
    "if",
    "not",
    "then",
)


def _local_ref(
    root: dict[str, object], ref: str, anchors: dict[str, dict[str, object] | None] | None
) -> object | None:
    if not ref.startswith("#") or anchors is None:
        return None
    fragment = ref[1:]
    if not fragment:
        return root
    if not fragment.startswith("/"):
        return anchors.get(fragment)
    if re.search(r"%(?![0-9A-Fa-f]{2})", fragment):
        return None
    try:
        fragment = unquote(fragment, errors="strict")
    except UnicodeDecodeError:
        return None
    current: object = root
    for part in fragment[1:].split("/"):
        if re.search(r"~(?![01])", part):
            return None
        token = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(token)
        elif (
            isinstance(current, list)
            and re.fullmatch(r"0|[1-9][0-9]*", token)
            and len(token) <= len(str(len(current)))
            and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            return None
    return current


def _schema_children(node: dict[str, object], *, include_definitions: bool) -> Iterator[dict[str, object]]:
    maps = _SCHEMA_MAP_KEYWORDS + (("$defs", "definitions") if include_definitions else ())
    for key in maps:
        value = node.get(key)
        if isinstance(value, dict):
            yield from (child for child in value.values() if isinstance(child, dict))
    for key in _SCHEMA_ARRAY_KEYWORDS:
        value = node.get(key)
        if isinstance(value, list):
            yield from (child for child in value if isinstance(child, dict))
    for key in _SINGLE_SCHEMA_KEYWORDS:
        value = node.get(key)
        if isinstance(value, dict):
            yield value
        elif key == "items" and isinstance(value, list):
            yield from (child for child in value if isinstance(child, dict))


def _walk_nodes(
    root: dict[str, object],
    *,
    include_definitions: bool,
    incomplete_reasons: list[str],
    anchors: dict[str, dict[str, object] | None] | None = None,
) -> list[dict[str, object]]:
    stack = [root]
    seen: set[int] = set()
    nodes: list[dict[str, object]] = []
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        if len(seen) >= _MAX_SCHEMA_NODES:
            if "node_budget_exceeded" not in incomplete_reasons:
                incomplete_reasons.append("node_budget_exceeded")
            break
        seen.add(id(node))
        nodes.append(node)
        ref = node.get("$ref") if not include_definitions else None
        if isinstance(ref, str):
            target = _local_ref(root, ref, anchors)
            if isinstance(target, dict):
                stack.append(target)
            elif ref.startswith("#") and not isinstance(target, bool):
                reason = (
                    "node_budget_exceeded"
                    if "node_budget_exceeded" in incomplete_reasons
                    else "local_ref_unresolved"
                )
                if reason not in incomplete_reasons:
                    incomplete_reasons.append(reason)
        stack.extend(_schema_children(node, include_definitions=include_definitions))
    return nodes


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


def _schema_rules(
    tool: ToolInfo, schema: dict[str, object], *, incomplete_reasons: list[str]
) -> list[SchemaFinding]:
    findings: list[SchemaFinding] = []
    reachability_incomplete: list[str] = []
    all_nodes = _walk_nodes(schema, include_definitions=True, incomplete_reasons=reachability_incomplete)
    anchors: dict[str, dict[str, object] | None] = {}
    for node in all_nodes:
        anchor = node.get("$anchor")
        if isinstance(anchor, str):
            anchors[anchor] = None if anchor in anchors else node
    # Embedded resources change reference scope; a partial inventory cannot
    # establish anchor uniqueness or rule out an unseen resource boundary.
    reference_anchors = (
        None
        if reachability_incomplete or any(node is not schema and "$id" in node for node in all_nodes)
        else anchors
    )
    reachable = _walk_nodes(
        schema,
        include_definitions=False,
        incomplete_reasons=reachability_incomplete,
        anchors=reference_anchors,
    )
    for reason in reachability_incomplete:
        if reason not in incomplete_reasons:
            incomplete_reasons.append(reason)
    reachable_ids = {id(node) for node in reachable}
    headers: dict[str, str] = {}
    for node in all_nodes:
        if "x-mcp-header" not in node:
            continue
        header = node["x-mcp-header"]
        if id(node) not in reachable_ids:
            # Incomplete resolution cannot establish that a branch is unreachable.
            if reachability_incomplete:
                continue
            findings.append(
                SchemaFinding(
                    tool_name=tool.name,
                    kind="header_unreachable",
                    evidence=["x-mcp-header appears outside a reachable schema branch"],
                )
            )
            continue
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
    for node in all_nodes:
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


def scan_tool_schema(
    tool: ToolInfo, *, server_url: str | None = None, incomplete_reasons: list[str] | None = None
) -> list[SchemaFinding]:
    """Inspect metadata offline, recording incomplete traversal when a collector is supplied."""
    findings: list[SchemaFinding] = []
    reasons = incomplete_reasons if incomplete_reasons is not None else []
    for schema in (tool.input_schema, tool.output_schema):
        if isinstance(schema, dict):
            findings.extend(_schema_rules(tool, schema, incomplete_reasons=reasons))
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
