"""Fixture-backed tests for offline tool-schema rules."""

from __future__ import annotations

import pytest

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
