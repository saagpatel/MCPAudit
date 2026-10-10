"""Fixture-backed tests for offline tool-schema rules."""

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mcp_audit.models import ToolInfo
from mcp_audit.schema_rules import scan_tool_schema


@pytest.mark.parametrize(
    ("schema", "kind"),
    [
        (
            {"type": "object", "properties": {"token": {"type": "string", "x-mcp-header": "Bad Header"}}},
            "header_invalid",
        ),
        (
            {
                "type": "object",
                "properties": {
                    "a": {"type": "string", "x-mcp-header": "X-Key"},
                    "b": {"type": "string", "x-mcp-header": "x-key"},
                },
            },
            "header_duplicate",
        ),
        ({"type": "object", "properties": {"a": {"type": "object", "x-mcp-header": "X-Key"}}}, "header_type"),
        (
            {
                "type": "object",
                "properties": {"api_token": {"type": "string", "x-mcp-header": "Authorization"}},
            },
            "credential_header",
        ),
        (
            {"type": "object", "properties": {"x": {"$ref": "https://schemas.example.test/value"}}},
            "external_ref",
        ),
    ],
)
def test_schema_rule_fixtures(schema: dict[str, object], kind: str) -> None:
    tool = ToolInfo(name="fixture", input_schema=schema)
    assert kind in {finding.kind for finding in scan_tool_schema(tool)}


def test_header_annotation_in_unreferenced_definition_is_flagged() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "type": "object",
            "properties": {},
            "$defs": {"unused": {"type": "string", "x-mcp-header": "X-Unused"}},
        },
    )
    assert "header_unreachable" in {finding.kind for finding in scan_tool_schema(tool)}


@pytest.mark.parametrize(
    ("icon", "server_url", "kind"),
    [
        ({"src": "http://example.test/icon.png"}, "https://example.test/mcp", "icon_source"),
        ({"src": "https://cdn.example.test/icon.png"}, "https://example.test/mcp", "icon_origin"),
    ],
)
def test_icon_rule_fixtures(icon: dict[str, object], server_url: str, kind: str) -> None:
    tool = ToolInfo(name="fixture", icons=[icon])
    assert kind in {finding.kind for finding in scan_tool_schema(tool, server_url=server_url)}


def test_external_ref_is_low_and_same_origin_icon_is_accepted() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={"$ref": "https://schemas.example.test/value"},
        icons=[{"src": "https://example.test:443/icon.png"}],
    )
    findings = scan_tool_schema(tool, server_url="https://example.test/mcp")
    assert [(finding.kind, finding.severity) for finding in findings] == [("external_ref", "low")]


@pytest.mark.parametrize(
    "keyword",
    [
        "items",
        "additionalItems",
        "additionalProperties",
        "contains",
        "unevaluatedItems",
        "unevaluatedProperties",
        "propertyNames",
        "contentSchema",
        "if",
        "then",
        "else",
        "not",
    ],
)
def test_single_schema_header_is_reachable(keyword: str) -> None:
    tool = ToolInfo(name="fixture", input_schema={keyword: {"type": "string", "x-mcp-header": "X-Value"}})
    assert scan_tool_schema(tool) == []


@pytest.mark.parametrize("keyword", ["if", "then", "else", "items", "allOf", "prefixItems"])
@pytest.mark.parametrize("surface", ["input_schema", "output_schema"])
def test_credential_header_in_conditional_and_array_branches(keyword: str, surface: str) -> None:
    branch = {"properties": {"api_token": {"type": "string", "x-mcp-header": "Authorization"}}}
    schema = {keyword: [branch] if keyword in {"allOf", "prefixItems"} else branch}
    tool = ToolInfo.model_validate({"name": "fixture", surface: schema})
    assert [finding.kind for finding in scan_tool_schema(tool)] == ["credential_header"]


def test_legacy_tuple_items_header_is_reachable() -> None:
    tool = ToolInfo(name="fixture", input_schema={"items": [{"type": "string", "x-mcp-header": "X-Value"}]})
    assert scan_tool_schema(tool) == []


@pytest.mark.parametrize("keyword", ["$defs", "definitions"])
def test_definition_schemas_are_inspected_and_local_references_are_reachable(keyword: str) -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "$ref": f"#/{keyword}/used",
            keyword: {
                "used": {"type": "string", "x-mcp-header": "X-Used"},
                "unused": {"$ref": "https://schemas.example.test/value", "x-mcp-header": "X-Unused"},
            },
        },
    )
    assert [finding.kind for finding in scan_tool_schema(tool)] == ["header_unreachable", "external_ref"]


@pytest.mark.parametrize("surface", ["input_schema", "output_schema"])
@pytest.mark.parametrize(
    ("ref", "key", "anchor"),
    [
        ("#value", "value", "value"),
        ("#/$defs/a%20b", "a b", None),
        ("#/%24defs/a%20b", "a b", None),
        ("#/$defs/a%7E1b%7E0c", "a/b~c", None),
    ],
)
def test_local_anchor_and_encoded_pointer_headers_are_reachable(
    surface: str, ref: str, key: str, anchor: str | None
) -> None:
    target = {"type": "string", "x-mcp-header": "X-Value"}
    if anchor is not None:
        target["$anchor"] = anchor
    definitions: dict[str, object] = {key: target}
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"value": {"$ref": ref}},
        "$defs": definitions,
    }
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({"value": "fixture"})
    incomplete: list[str] = []
    tool = ToolInfo.model_validate({"name": "fixture", surface: schema})
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == []
    definitions["unused"] = {"type": "string", "x-mcp-header": "X-Unused"}
    tool = ToolInfo.model_validate({"name": "fixture", surface: schema})
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=incomplete)] == [
        "header_unreachable"
    ]
    assert incomplete == []


@pytest.mark.parametrize(
    "ref",
    [
        "#missing",
        "#/$defs/missing",
        "#/$defs/value%",
        "#/$defs/%FF",
        "#/$defs/value~2",
        "#%76alue",
        "#%2F$defs/value",
    ],
)
def test_unresolved_local_reference_reports_incomplete_reachability(ref: str) -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "properties": {
                "a": {"$ref": ref},
                "b": {"$ref": ref},
                "visited": {"type": "string", "x-mcp-header": "Bad Header"},
            },
            "$defs": {"value": {"$anchor": "value", "type": "string", "x-mcp-header": "X-Value"}},
        },
    )
    incomplete: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=incomplete)] == [
        "header_invalid"
    ]
    assert incomplete == ["local_ref_unresolved"]


@pytest.mark.parametrize("ambiguous_resource", [False, True])
def test_ambiguous_anchor_resolution_reports_incomplete_reachability(ambiguous_resource: bool) -> None:
    target = {"$anchor": "value", "type": "string", "x-mcp-header": "X-Value"}
    other = {"$anchor": "value", "type": "string"}
    if ambiguous_resource:
        other["$id"] = "https://schemas.example.test/embedded"
    tool = ToolInfo(name="fixture", input_schema={"$ref": "#value", "$defs": {"a": target, "b": other}})
    incomplete: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == ["local_ref_unresolved"]


def test_anchor_lookup_ignores_instance_payloads_and_obeys_the_node_budget() -> None:
    schema: dict[str, object] = {
        "$ref": "#value",
        "examples": [{"$anchor": "value", "type": "string", "x-mcp-header": "Bad Header"}],
    }
    incomplete: list[str] = []
    assert (
        scan_tool_schema(ToolInfo(name="fixture", input_schema=schema), incomplete_reasons=incomplete) == []
    )
    assert incomplete == ["local_ref_unresolved"]
    schema["$defs"] = {f"ordinary_{index}": {"type": "string"} for index in range(2050)}
    incomplete = []
    assert (
        scan_tool_schema(ToolInfo(name="fixture", input_schema=schema), incomplete_reasons=incomplete) == []
    )
    assert incomplete == ["node_budget_exceeded"]


def test_anchor_cycle_is_finite_and_reachable_headers_are_checked() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "$ref": "#value",
            "$defs": {"value": {"$anchor": "value", "$ref": "#value", "x-mcp-header": "Bad Header"}},
        },
    )
    incomplete: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=incomplete)] == [
        "header_invalid",
        "header_type",
    ]
    assert incomplete == []


@pytest.mark.parametrize("keyword", ["examples", "default", "const", "enum", "x-instance-data"])
@pytest.mark.parametrize("in_definition", [False, True])
def test_instance_payloads_are_not_schema_declarations(keyword: str, in_definition: bool) -> None:
    data = {
        "$ref": "https://example.test/not-a-schema",
        "x-mcp-header": "ordinary data",
        "properties": {"api_token": {"type": "string", "x-mcp-header": "Authorization"}},
    }
    schema: dict[str, object] = {
        "type": "object",
        keyword: [data] if keyword in {"examples", "enum"} else data,
    }
    if in_definition:
        schema = {"$defs": {"unused": schema}}
    assert scan_tool_schema(ToolInfo(name="fixture", input_schema=schema)) == []


def test_null_header_declaration_is_invalid() -> None:
    tool = ToolInfo(
        name="fixture", input_schema={"properties": {"value": {"type": "string", "x-mcp-header": None}}}
    )
    assert [finding.kind for finding in scan_tool_schema(tool)] == ["header_invalid"]


@pytest.mark.parametrize("surface", ["input_schema", "output_schema"])
@pytest.mark.parametrize("container", ["properties", "$defs"])
def test_schema_budget_exhaustion_is_reported(surface: str, container: str) -> None:
    branches = {"dangerous": {"$ref": "https://schemas.example.test/unvisited"}}
    branches.update({f"ordinary_{index}": {"type": "string"} for index in range(2050)})
    tool = ToolInfo.model_validate({"name": "fixture", surface: {container: branches}})
    incomplete: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == ["node_budget_exceeded"]


def test_schema_budget_retains_visited_findings() -> None:
    branches: dict[str, object] = {f"ordinary_{index}": {"type": "string"} for index in range(2050)}
    branches["dangerous"] = {"$ref": "https://schemas.example.test/visited"}
    incomplete: list[str] = []
    findings = scan_tool_schema(
        ToolInfo(name="fixture", input_schema={"properties": branches}), incomplete_reasons=incomplete
    )
    assert [finding.kind for finding in findings] == ["external_ref"]
    assert incomplete == ["node_budget_exceeded"]


def test_incomplete_reachability_does_not_misclassify_a_referenced_header() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "$ref": "#/$defs/header",
            "$defs": {"header": {"type": "string", "x-mcp-header": "X-Value"}},
            "properties": {f"ordinary_{index}": {"type": "string"} for index in range(2050)},
        },
    )
    incomplete: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == ["node_budget_exceeded"]


def test_exact_schema_budget_and_reference_cycle_do_not_report_exhaustion() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "$ref": "#",
            "properties": {f"ordinary_{index}": {"type": "string"} for index in range(2047)},
        },
    )
    incomplete: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == []


def test_header_type_follows_local_references() -> None:
    def schema(target: dict[str, object]) -> dict[str, object]:
        return {
            "type": "object",
            "properties": {"value": {"$ref": "#/$defs/text", "x-mcp-header": "X-Value"}},
            "$defs": {"text": target},
        }

    ok = ToolInfo(name="t", input_schema=schema({"type": "string"}))
    assert [f.kind for f in scan_tool_schema(ok)] == []
    bad = ToolInfo(name="t", input_schema=schema({"type": "object"}))
    assert [f.kind for f in scan_tool_schema(bad)] == ["header_type"]
    cyclic = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"value": {"$ref": "#/$defs/a", "x-mcp-header": "X-Value"}},
            "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}},
        },
    )
    assert [f.kind for f in scan_tool_schema(cyclic)] == ["header_type"]
    broken = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"value": {"$ref": "#/$defs/missing", "x-mcp-header": "X"}},
        },
    )
    reasons: list[str] = []
    assert "header_type" not in [f.kind for f in scan_tool_schema(broken, incomplete_reasons=reasons)]
    assert reasons
