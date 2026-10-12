"""Static, offline checks for tool schema extensions and metadata."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import ParseResult, unquote, urlparse

from mcp_audit.models import SchemaFinding, ToolInfo
from mcp_audit.ssrf import _word_tokens

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
_CHILD_KEYWORD_ORDER = {
    key: index
    for index, key in enumerate(
        (*_SCHEMA_MAP_KEYWORDS, "$defs", "definitions", *_SCHEMA_ARRAY_KEYWORDS, *_SINGLE_SCHEMA_KEYWORDS)
    )
}


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


_MAX_REF_HOPS = 64
_COMPOSITION_KEYWORDS = ("allOf", "anyOf", "oneOf")
_ALL_TYPES = _PRIMITIVE_TYPES | {"object", "array", "null"}
_UNSUPPORTED_REFERENCES = ("$dynamicRef", "$recursiveRef")
_HeaderTypes = dict[int, tuple[set[str], bool]]


def _effective_header_types(
    root: dict[str, object], node: dict[str, object], anchors: dict[str, dict[str, object] | None] | None
) -> tuple[_HeaderTypes, bool]:
    """Bounded type constraints: intersect refs/allOf, union anyOf/oneOf alternatives.

    This is type coverage, not full JSON Schema validation. In particular, oneOf
    exclusivity cannot enlarge the union of the declared branch types.
    """
    remaining = _MAX_SCHEMA_NODES

    def combine_headers(
        groups: list[tuple[_HeaderTypes, bool]], types: set[str], *, alternatives: bool = False
    ) -> _HeaderTypes:
        unresolved = sum(not resolved for _headers, resolved in groups)
        result: _HeaderTypes = {}
        for headers, resolved in groups:
            siblings_resolved = alternatives or unresolved == int(not resolved)
            for identity, (allowed, header_resolved) in headers.items():
                allowed = allowed & types
                header_resolved &= siblings_resolved
                if identity in result:
                    previous_types, previous_resolved = result[identity]
                    allowed |= previous_types
                    header_resolved &= previous_resolved
                result[identity] = allowed, header_resolved
        return result

    def visit(current: object, depth: int, active: frozenset[int]) -> tuple[set[str], _HeaderTypes, bool]:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth >= _MAX_REF_HOPS:
            return set(), {}, False
        if isinstance(current, bool):
            return set(_ALL_TYPES) if current else set(), {}, True
        if not isinstance(current, dict) or id(current) in active:
            return set(), {}, False
        active = active | {id(current)}
        types = set(_ALL_TYPES)
        resolved = not any(key in current for key in _UNSUPPORTED_REFERENCES)
        header_types: _HeaderTypes = (
            {id(current): (set(_ALL_TYPES), resolved)} if "x-mcp-header" in current else {}
        )
        if "type" in current:
            raw_type = current["type"]
            if isinstance(raw_type, str) and raw_type in _ALL_TYPES:
                types = {raw_type}
            elif (
                isinstance(raw_type, list)
                and raw_type
                and all(isinstance(value, str) and value in _ALL_TYPES for value in raw_type)
            ):
                types = {value for value in raw_type if isinstance(value, str)}
            else:
                return (
                    set(),
                    {identity: (allowed, False) for identity, (allowed, _) in header_types.items()},
                    False,
                )
            # Integers are also numbers; expansion makes intersections accurate.
            if "number" in types:
                types.add("integer")
        groups = [(header_types, resolved)]
        if "$ref" in current:
            ref = current["$ref"]
            target = _local_ref(root, ref, anchors) if isinstance(ref, str) else None
            child_types, child_headers, child_resolved = visit(target, depth + 1, active)
            types &= child_types
            groups.append((child_headers, child_resolved))
        for keyword in _COMPOSITION_KEYWORDS:
            if keyword not in current:
                continue
            branches = current[keyword]
            if not isinstance(branches, list) or not branches:
                groups.append(({}, False))
                continue
            combined = set(_ALL_TYPES) if keyword == "allOf" else set()
            branch_groups: list[tuple[_HeaderTypes, bool]] = []
            for branch in branches:
                child_types, child_headers, child_resolved = visit(branch, depth + 1, active)
                if keyword == "allOf":
                    combined &= child_types
                else:
                    combined |= child_types
                branch_groups.append((child_headers, child_resolved))
                if remaining < 0:
                    break
            types &= combined
            groups.append(
                (
                    combine_headers(branch_groups, combined, alternatives=keyword != "allOf"),
                    all(child_resolved for _headers, child_resolved in branch_groups),
                )
            )
        # A header retains the constraints of its own alternative, then inherits
        # same-value constraints from references, siblings, and enclosing nodes.
        # Unresolved alternatives affect coverage, but only applicable constraints
        # affect the resolution of an individual header declaration.
        return types, combine_headers(groups, types), all(resolved for _headers, resolved in groups)

    _types, header_types, resolved = visit(node, 0, frozenset())
    return header_types, resolved


def _property_headers(
    root: dict[str, object], prop: object, anchors: dict[str, dict[str, object] | None] | None
) -> tuple[list[dict[str, object]], bool]:
    """Header declarations for one instance slot, through local refs and composition.

    Each declaration is returned once per slot even when alternatives reach it.
    Nested properties and instance payloads describe other values.
    """
    stack = [(prop, 0, frozenset[int]())]
    seen: set[int] = set()
    headers: list[dict[str, object]] = []
    resolved = True
    remaining = _MAX_SCHEMA_NODES
    while stack:
        current, depth, active = stack.pop()
        remaining -= 1
        if remaining < 0:
            return headers, False
        if depth >= _MAX_REF_HOPS:
            resolved = False
            continue
        if isinstance(current, bool):
            continue
        if not isinstance(current, dict) or id(current) in active:
            resolved = False
            continue
        # A repeated DAG node is covered, but a recursive path is unresolved.
        if id(current) in seen:
            continue
        seen.add(id(current))
        active = active | {id(current)}
        if "x-mcp-header" in current:
            headers.append(current)
        if any(key in current for key in _UNSUPPORTED_REFERENCES):
            resolved = False
        if "$ref" in current:
            ref = current["$ref"]
            target = _local_ref(root, ref, anchors) if isinstance(ref, str) else None
            stack.append((target, depth + 1, active))
        for keyword in _COMPOSITION_KEYWORDS:
            if keyword not in current:
                continue
            branches = current[keyword]
            if not isinstance(branches, list) or not branches:
                resolved = False
                continue
            # Bound pending work as well as visits, including sibling applicators.
            available = max(0, remaining - len(stack))
            if len(branches) > available:
                resolved = False
            stack.extend((branch, depth + 1, active) for branch in branches[:available])
    return headers, resolved


def _value_slots(node: dict[str, object]) -> Iterator[tuple[str | None, object]]:
    """Schemas that describe instance values, with the property name when there is one."""
    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, prop in properties.items():
            if isinstance(name, str):
                yield name, prop
    patterns = node.get("patternProperties")
    if isinstance(patterns, dict):
        yield from ((None, prop) for prop in patterns.values())
    for keyword in ("additionalProperties", "items"):
        if isinstance(node.get(keyword), dict):
            yield None, node[keyword]
    prefix = node.get("prefixItems")
    if isinstance(prefix, list):
        yield from ((None, item) for item in prefix)


def _schema_children(node: dict[str, object], *, include_definitions: bool) -> Iterator[dict[str, object]]:
    # Visit only present schema keywords, in the same budget-sensitive order.
    for key in sorted(node.keys() & _CHILD_KEYWORD_ORDER.keys(), key=_CHILD_KEYWORD_ORDER.__getitem__):
        value = node[key]
        if key in (*_SCHEMA_MAP_KEYWORDS, "$defs", "definitions"):
            if key in {"$defs", "definitions"} and not include_definitions:
                continue
            if isinstance(value, dict):
                yield from (child for child in value.values() if isinstance(child, dict))
        elif key in _SCHEMA_ARRAY_KEYWORDS or (key == "items" and isinstance(value, list)):
            if isinstance(value, list):
                yield from (child for child in value if isinstance(child, dict))
        elif isinstance(value, dict):
            yield value


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
    uses: list[tuple[str | None, list[dict[str, object]]]] = []
    contexts: dict[int, list[dict[str, object]]] = {}
    type_cache: dict[int, tuple[_HeaderTypes, bool]] = {}
    same_value_children: set[int] = set()
    for node in reachable:
        ref = node.get("$ref")
        target = _local_ref(schema, ref, reference_anchors) if isinstance(ref, str) else None
        if isinstance(target, dict):
            same_value_children.add(id(target))
        for keyword in _COMPOSITION_KEYWORDS:
            branches = node.get(keyword)
            if isinstance(branches, list):
                same_value_children.update(
                    id(branch) for branch in branches[:_MAX_SCHEMA_NODES] if isinstance(branch, dict)
                )
    # Root and standalone schema branches also provide same-value constraints.
    for node in reachable:
        if node is schema or id(node) not in same_value_children:
            declarations, resolved = _property_headers(schema, node, reference_anchors)
            if not resolved and (
                declarations
                or any(key in node for key in ("$ref", *_COMPOSITION_KEYWORDS, *_UNSUPPORTED_REFERENCES))
            ):
                reason = "x-mcp-header use could not be resolved for a property"
                if not reachability_incomplete and reason not in incomplete_reasons:
                    incomplete_reasons.append(reason)
            for declaration in declarations:
                contexts.setdefault(id(declaration), []).append(node)
    for node in reachable:
        for name, slot in _value_slots(node):
            declarations, resolved = _property_headers(schema, slot, reference_anchors)
            if not resolved:
                reason = "x-mcp-header use could not be resolved for a property"
                if not reachability_incomplete and reason not in incomplete_reasons:
                    incomplete_reasons.append(reason)
            uses.append((name, declarations))
            if isinstance(slot, dict):
                for declaration in declarations:
                    contexts.setdefault(id(declaration), []).append(slot)
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
        invalid_type = False
        # Constraints may live beside an annotation in another allOf branch.
        for context in contexts.get(id(node), [node]):
            if id(context) not in type_cache:
                type_cache[id(context)] = _effective_header_types(schema, context, reference_anchors)
            header_types, resolved = type_cache[id(context)]
            types, header_resolved = header_types.get(id(node), (set(), False))
            if not resolved or not header_resolved:
                reason = "x-mcp-header type could not be resolved through local refs or composition"
                if reason not in incomplete_reasons:
                    incomplete_reasons.append(reason)
            if header_resolved and (not types or not types <= _PRIMITIVE_TYPES):
                invalid_type = True
        if invalid_type:
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
    # Header checks apply per instance slot: a shared definition reached through a
    # local $ref counts once for each property, item or pattern slot that uses it.
    for name, declarations in uses:
        slot_headers: set[str] = set()
        for declaration in declarations:
            header = declaration["x-mcp-header"]
            if not isinstance(header, str) or not _HEADER_TOKEN.fullmatch(header):
                continue
            if header.casefold() in slot_headers:
                continue
            slot_headers.add(header.casefold())
            if header.casefold() in headers:
                findings.append(
                    SchemaFinding(
                        tool_name=tool.name,
                        kind="header_duplicate",
                        evidence=[f"x-mcp-header duplicates {headers[header.casefold()]}"],
                    )
                )
            else:
                headers[header.casefold()] = header
            # A credential-looking parameter mapped to a request header duplicates the
            # credential's transport declaration and can make schema consumers disagree.
            if name is not None and {word.lower() for word in _word_tokens(name)} & _CREDENTIAL_WORDS:
                findings.append(
                    SchemaFinding(
                        tool_name=tool.name,
                        kind="credential_header",
                        evidence=[f"credential-looking parameter {name} is mirrored to a header"],
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
