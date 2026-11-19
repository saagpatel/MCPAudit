"""The SSRF schema walker must follow every same-document `$ref` form.

docs/OUTPUT-CONTRACT.md says permission inference "inspects reachable nested
property names through the bounded SSRF schema walker, including objects,
array items, composition branches, and same-document `$ref` targets", and that
for the schema metadata rules "Local references establish reachability through
local `$anchor` declarations and percent-decoded JSON Pointer fragments".

The SSRF walker used to resolve only plain JSON Pointer refs (`#/$defs/Request`),
so a URL parameter reached through a local `$anchor` (`#node`) or a
percent-encoded pointer (`#/$defs/a%20b`) dropped to the medium
schema_traversal_incomplete fallback while the schema rules resolved it.

The anchor and percent-encoded forms now resolve like the plain form. An anchor
that is declared twice, or sits under an embedded `$id` scope, stays visibly
incomplete.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import SsrfSeverity, ToolInfo
from mcp_audit.ssrf import SsrfDetector, _iter_schema_properties, _schema_pointer_index

URL_DEF: dict[str, Any] = {"type": "object", "properties": {"url": {"type": "string"}}}

SCHEMAS: dict[str, dict[str, Any]] = {
    "plain-pointer": {
        "type": "object",
        "properties": {"t": {"$ref": "#/$defs/n"}},
        "$defs": {"n": URL_DEF},
    },
    "anchor": {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"n": {"$anchor": "node", **URL_DEF}},
    },
    "percent-encoded-pointer": {
        "type": "object",
        "properties": {"t": {"$ref": "#/$defs/a%20b"}},
        "$defs": {"a b": URL_DEF},
    },
}


@pytest.mark.parametrize("form", list(SCHEMAS))
def test_same_document_ref_forms_reach_the_url_parameter(form: str) -> None:
    tool = ToolInfo(name="fetch_doc", description="Fetch a document.", input_schema=SCHEMAS[form])
    findings = SsrfDetector().scan_server([tool], [])
    assert [(f.severity, f.pattern_name) for f in findings] == [
        (SsrfSeverity.HIGH, "url_param_with_fetch_verb")
    ]


AMBIGUOUS: dict[str, dict[str, Any]] = {
    "duplicate-anchor": {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"a": {"$anchor": "node", **URL_DEF}, "b": {"$anchor": "node", **URL_DEF}},
    },
    "embedded-id-scope": {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"n": {"$id": "https://example.test/inner", "$anchor": "node", **URL_DEF}},
    },
}


@pytest.mark.parametrize("form", list(AMBIGUOUS))
def test_ambiguous_anchor_stays_visibly_incomplete(form: str) -> None:
    tool = ToolInfo(name="fetch_doc", description="Fetch a document.", input_schema=AMBIGUOUS[form])
    findings = SsrfDetector().scan_server([tool], [])
    assert [(f.severity, f.pattern_name) for f in findings] == [
        (SsrfSeverity.MEDIUM, "schema_traversal_incomplete")
    ]


SHELL_DEF: dict[str, Any] = {"type": "object", "properties": {"shell_command": {"type": "string"}}}


def _dereference(document: dict[str, Any], pointer: str) -> object:
    node: object = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        assert isinstance(node, dict) and token in node, pointer
        node = node[token]
    return node


def _shell_findings(properties: dict[str, Any], defs: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    tool = ToolInfo(
        name="helper",
        description="Helper.",
        input_schema={"type": "object", "properties": properties, "$defs": defs},
    )
    findings = PermissionAnalyzer().analyze_tool(tool)
    for finding in findings:
        for path in finding.field_paths:
            _dereference({"input_schema": tool.input_schema}, path)
    return [(f.category.value, f.confidence.value, f.field_paths) for f in findings]


@pytest.mark.parametrize(
    ("properties", "defs"),
    [
        ({"t": {"$ref": "#node"}}, {"n": {"$anchor": "node", **SHELL_DEF}}),
        ({"t": {"$ref": "#/$defs/a%20b"}}, {"a b": SHELL_DEF}),
        ({"a": {"$ref": "#node"}, "b": {"$ref": "#/$defs/n"}}, {"n": {"$anchor": "node", **SHELL_DEF}}),
    ],
    ids=["anchor", "percent-encoded", "mixed-anchor-and-pointer"],
)
def test_resolved_refs_give_canonical_field_paths_and_count_once(
    properties: dict[str, Any], defs: dict[str, Any]
) -> None:
    plain = _shell_findings({"t": {"$ref": "#/$defs/n"}}, {"n": SHELL_DEF})
    found = _shell_findings(properties, defs)
    assert [(category, confidence) for category, confidence, _ in found] == [
        (category, confidence) for category, confidence, _ in plain
    ]
    for _, _, paths in found:
        assert all(path.endswith("/properties/shell_command") for path in paths)
        assert len(paths) == len(set(paths))


def _anchored_schema_with_payload(payload_key: str, payload: object) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"n": {"$anchor": "node", **URL_DEF}},
        payload_key: payload,
    }


def _deep_default(levels: int, key_length: int) -> dict[str, Any]:
    node: dict[str, Any] = {}
    for _ in range(levels):
        node = {"k" * key_length: node}
    return node


@pytest.mark.parametrize(
    ("payload_key", "payload"),
    [
        ("examples", [{} for _ in range(100_000)]),
        ("default", _deep_default(400, 2_048)),
    ],
    ids=["wide-examples", "deep-default"],
)
def test_pointer_index_ignores_instance_payloads(payload_key: str, payload: object) -> None:
    schema = _anchored_schema_with_payload(payload_key, payload)
    index = _schema_pointer_index(schema)
    assert len(index) <= 4
    assert max(len(pointer) for pointer in index.values()) < 64
    for pointer_paths in (False, True):
        walk = _iter_schema_properties(schema, pointer_paths=pointer_paths)
        assert walk.incomplete_reasons == []
        assert [name for _, name, _ in walk.properties] == ["t", "url"]


def _peak_bytes(build: Any) -> int:
    import tracemalloc

    tracemalloc.start()
    try:
        build()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize(
    "wide_def",
    [
        {"allOf": [True] * 100_000},
        {"anyOf": [False] * 100_000},
        {"items": [True] * 100_000},
        {"properties": {f"p{i}": True for i in range(100_000)}},
    ],
    ids=["allOf-booleans", "anyOf-booleans", "legacy-items-booleans", "properties-booleans"],
)
def test_pointer_index_bounds_allocation_on_wide_containers(wide_def: dict[str, Any]) -> None:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"wide": wide_def, "n": {"$anchor": "node", **URL_DEF}},
    }
    index: dict[int, str] = {}
    peak = _peak_bytes(lambda: index.update(_schema_pointer_index(schema)))
    # The round-3 version allocated about 12 MB here; the lazy walk stays far below 1 MB.
    assert peak < 512 * 1024, peak
    assert len(index) <= 8


@pytest.mark.parametrize(
    "wide_def",
    [
        {"allOf": [{} for _ in range(200_000)]},
        {"properties": {f"p{i}": {} for i in range(200_000)}},
        {"allOf": [True] * 200_000},
    ],
    ids=["allOf-empty-schemas", "properties-empty-schemas", "allOf-booleans"],
)
def test_anchor_inventory_walk_bounds_pending_work(wide_def: dict[str, Any]) -> None:
    from mcp_audit.schema_rules import _walk_nodes

    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"n": {"$anchor": "node", **URL_DEF}, "wide": wide_def},
    }
    reasons: list[str] = []
    peak = _peak_bytes(lambda: _walk_nodes(schema, include_definitions=True, incomplete_reasons=reasons))
    # The unbounded walk queued every child first (about 1.6 MB for 200,000 empty schemas).
    assert peak < 512 * 1024, peak
    assert reasons == ["node_budget_exceeded"]
    # An incomplete inventory cannot vouch for anchors, so the ref stays visibly incomplete.
    findings = SsrfDetector().scan_server(
        [ToolInfo(name="fetch_doc", description="Fetch a document.", input_schema=schema)], []
    )
    assert [(f.severity, f.pattern_name) for f in findings] == [
        (SsrfSeverity.MEDIUM, "schema_traversal_incomplete")
    ]
