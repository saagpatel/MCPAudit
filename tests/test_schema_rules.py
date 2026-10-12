"""Fixture-backed tests for offline tool-schema rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mcp_audit.models import ToolInfo
from mcp_audit.schema_rules import _schema_children, scan_tool_schema


@pytest.mark.parametrize("include_definitions", [False, True])
def test_schema_children_preserve_keyword_and_mapping_order(include_definitions: bool) -> None:
    schema = {
        "items": [{"title": "item"}, False],
        "allOf": [{"title": "composition"}, None],
        "$defs": {"one": {"title": "definition"}},
        "properties": {"b": {"title": "first"}, "a": {"title": "second"}},
        "additionalProperties": {"title": "additional"},
        "examples": [{"title": "instance payload"}],
        "type": "object",
    }
    children = list(_schema_children(schema, include_definitions=include_definitions))
    titles = [child["title"] for child in children]
    assert titles == [
        "first",
        "second",
        *(["definition"] if include_definitions else []),
        "composition",
        "item",
        "additional",
    ]


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
    ]
    assert incomplete


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


def test_exact_schema_budget_does_not_report_exhaustion_for_reference_cycle() -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "$ref": "#",
            "properties": {f"ordinary_{index}": {"type": "string"} for index in range(2047)},
        },
    )
    incomplete: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=incomplete) == []
    assert incomplete == ["x-mcp-header use could not be resolved for a property"]


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
    reasons: list[str] = []
    assert scan_tool_schema(cyclic, incomplete_reasons=reasons) == []
    assert reasons
    broken = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"value": {"$ref": "#/$defs/missing", "x-mcp-header": "X"}},
        },
    )
    reasons = []
    assert "header_type" not in [f.kind for f in scan_tool_schema(broken, incomplete_reasons=reasons)]
    assert reasons


@pytest.mark.parametrize("keyword", ["allOf", "anyOf", "oneOf"])
def test_composed_header_type_is_resolved(keyword: str) -> None:
    tool = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"value": {keyword: [{"type": "string"}], "x-mcp-header": "X-Value"}},
        },
    )
    reasons: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=reasons) == []
    assert reasons == []


def test_schema_findings_reach_the_default_summary() -> None:
    from mcp_audit.models import SchemaFinding
    from tests.test_terminal_summary import _connected, _render

    report = _connected()
    report.audits[0].schema_findings = [
        SchemaFinding(
            tool_name="t", kind="header_invalid", evidence=["x-mcp-header must be an RFC token string"]
        )
    ]
    assert report.ensure_review_summary().action_count == 1
    output = " ".join(_render(report).split())
    assert "Totals: 1 findings" in output or "Totals: 1 finding" in output


def test_header_checks_follow_local_references_per_property_use() -> None:
    token = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"api_token": {"$ref": "#/$defs/token"}},
            "$defs": {"token": {"type": "string", "x-mcp-header": "Authorization"}},
        },
    )
    findings = scan_tool_schema(token)
    assert [f.kind for f in findings] == ["credential_header"]
    assert "api_token" in findings[0].evidence[0]
    shared = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"a": {"$ref": "#/$defs/h"}, "b": {"$ref": "#/$defs/h"}},
            "$defs": {"h": {"type": "string", "x-mcp-header": "X-Value"}},
        },
    )
    assert [f.kind for f in scan_tool_schema(shared)] == ["header_duplicate"]


def test_inline_credential_header_evidence_names_the_parameter() -> None:
    tool = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"api_token": {"type": "string", "x-mcp-header": "Authorization"}},
        },
    )
    assert any("api_token" in f.evidence[0] for f in scan_tool_schema(tool) if f.kind == "credential_header")


@pytest.mark.parametrize("keyword", ["allOf", "anyOf", "oneOf"])
def test_composed_header_annotation_is_checked(keyword: str) -> None:
    tool = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {"api_token": {keyword: [{"type": "string", "x-mcp-header": "Authorization"}]}},
        },
    )
    reasons: list[str] = []
    assert [f.kind for f in scan_tool_schema(tool, incomplete_reasons=reasons)] == ["credential_header"]
    assert reasons == []


def test_long_local_reference_chain_reaches_header() -> None:
    defs: dict[str, object] = {f"r{i}": {"$ref": f"#/$defs/r{i + 1}"} for i in range(15)}
    defs["r15"] = {"type": "string", "x-mcp-header": "Authorization"}
    tool = ToolInfo(
        name="t",
        input_schema={"type": "object", "properties": {"api_token": {"$ref": "#/$defs/r0"}}, "$defs": defs},
    )
    assert "credential_header" in [f.kind for f in scan_tool_schema(tool)]


def test_distinct_schema_findings_stay_distinct_summary_actions() -> None:
    from mcp_audit.models import SchemaFinding
    from tests.test_terminal_summary import _connected

    report = _connected()
    report.audits[0].schema_findings = [
        SchemaFinding(
            tool_name="t", kind="header_invalid", evidence=["x-mcp-header must be an RFC token string"]
        ),
        SchemaFinding(
            tool_name="t",
            kind="credential_header",
            evidence=["credential-looking parameter api_token is mirrored to a header"],
        ),
    ]
    assert report.ensure_review_summary().action_count == 2


def test_composition_beside_ref_is_checked() -> None:
    tool = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {
                "api_token": {
                    "$ref": "#/$defs/plain",
                    "allOf": [{"type": "string", "x-mcp-header": "Authorization"}],
                }
            },
            "$defs": {"plain": {"type": "string"}},
        },
    )
    reasons: list[str] = []
    assert [f.kind for f in scan_tool_schema(tool, incomplete_reasons=reasons)] == ["credential_header"]
    assert reasons == []


@pytest.mark.parametrize(
    "schema",
    [
        {
            "prefixItems": [
                {"type": "string", "x-mcp-header": "X-Value"},
                {"type": "string", "x-mcp-header": "X-Value"},
            ]
        },
        {
            "patternProperties": {
                "^a$": {"type": "string", "x-mcp-header": "X-Value"},
                "^b$": {"type": "string", "x-mcp-header": "X-Value"},
            }
        },
        {
            "properties": {"a": {"type": "string", "x-mcp-header": "X-Value"}},
            "additionalProperties": {"type": "string", "x-mcp-header": "X-Value"},
        },
    ],
)
def test_duplicate_headers_outside_properties_are_found(schema: dict[str, object]) -> None:
    assert "header_duplicate" in [f.kind for f in scan_tool_schema(ToolInfo(name="t", input_schema=schema))]


@pytest.mark.parametrize("name", ["accessToken", "apiKey", "authToken"])
def test_camel_case_credential_names_match(name: str) -> None:
    tool = ToolInfo(
        name="t",
        input_schema={
            "type": "object",
            "properties": {name: {"type": "string", "x-mcp-header": "Authorization"}},
        },
    )
    assert "credential_header" in [f.kind for f in scan_tool_schema(tool)]


@pytest.mark.parametrize("surface", ["input_schema", "output_schema"])
@pytest.mark.parametrize(
    ("case", "kinds", "incomplete"),
    [
        ("allOf", ["credential_header"], False),
        ("anyOf", ["credential_header"], False),
        ("oneOf", ["credential_header"], False),
        ("nested_ref", ["credential_header"], False),
        ("ref_siblings", ["credential_header", "credential_header"], False),
        ("shared_slots", ["header_duplicate"], False),
        ("unresolved_branch", ["credential_header"], True),
    ],
)
def test_schema_composition_fixtures(surface: str, case: str, kinds: list[str], incomplete: bool) -> None:
    fixtures = json.loads((Path(__file__).parent / "fixtures" / "schema_composition.json").read_text())
    tool = ToolInfo.model_validate({"name": "fixture", surface: fixtures[case]})
    reasons: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)] == kinds
    assert bool(reasons) is incomplete


@pytest.mark.parametrize("keyword", ["allOf", "anyOf", "oneOf"])
@pytest.mark.parametrize("bad_type", ["object", "array", "null"])
def test_composition_does_not_accept_nonprimitive_header_types(keyword: str, bad_type: str) -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "properties": {
                "value": {keyword: [{"type": "string"}, {"type": bad_type}], "x-mcp-header": "X-Value"}
            }
        },
    )
    reasons: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)] == ["header_type"]
    assert reasons == []


@pytest.mark.parametrize("keyword", ["allOf", "anyOf", "oneOf"])
def test_composition_checks_invalid_and_duplicate_headers(keyword: str) -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "properties": {
                "a": {keyword: [{"type": "string", "x-mcp-header": "X-Value"}]},
                "b": {keyword: [{"type": "string", "x-mcp-header": "x-value"}]},
                "c": {keyword: [{"type": "string", "x-mcp-header": "Bad Header"}]},
            }
        },
    )
    reasons: list[str] = []
    assert sorted(finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)) == [
        "header_duplicate",
        "header_invalid",
    ]
    assert reasons == []


@pytest.mark.parametrize("surface", ["input_schema", "output_schema"])
def test_root_composition_inherits_sibling_type_constraints(surface: str) -> None:
    schema = {"allOf": [{"type": "string"}, {"x-mcp-header": "X-Value"}]}
    tool = ToolInfo.model_validate({"name": "fixture", surface: schema})
    reasons: list[str] = []
    assert scan_tool_schema(tool, incomplete_reasons=reasons) == []
    assert reasons == []


@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
def test_header_branch_type_does_not_inherit_unrelated_alternative(keyword: str) -> None:
    schema: dict[str, object] = {
        "properties": {
            "value": {keyword: [{"type": "string", "x-mcp-header": "X-Value"}, {"type": "object"}]}
        }
    }
    reasons: list[str] = []
    assert scan_tool_schema(ToolInfo(name="fixture", input_schema=schema), incomplete_reasons=reasons) == []
    assert reasons == []


@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
def test_nested_annotation_inherits_only_its_alternative_constraints(keyword: str) -> None:
    schema: dict[str, object] = {
        "properties": {
            "value": {
                keyword: [
                    {"allOf": [{"type": "string"}, {"x-mcp-header": "X-Value"}]},
                    {"type": "object"},
                ]
            }
        }
    }
    reasons: list[str] = []
    assert scan_tool_schema(ToolInfo(name="fixture", input_schema=schema), incomplete_reasons=reasons) == []
    assert reasons == []


@pytest.mark.parametrize(
    "branch",
    [
        {"$ref": "#/$defs/missing"},
        {"$ref": "https://schemas.example.test/value"},
        {"$ref": "#/$defs/cycle"},
        {"$dynamicRef": "#value"},
        {"$recursiveRef": "#"},
        {"$ref": None},
        {"allOf": []},
        {"anyOf": {}},
        {"oneOf": [None]},
        {"type": ["string", None]},
    ],
)
@pytest.mark.parametrize("direct_type", [False, True])
def test_unresolved_composition_never_silently_passes(branch: dict[str, object], direct_type: bool) -> None:
    prop: dict[str, object] = {"allOf": [branch], "x-mcp-header": "X-Value"}
    if direct_type:
        prop["type"] = "string"
    tool = ToolInfo(
        name="fixture",
        input_schema={
            "properties": {"value": prop},
            "$defs": {"cycle": {"$ref": "#/$defs/cycle"}},
        },
    )
    reasons: list[str] = []
    findings = scan_tool_schema(tool, incomplete_reasons=reasons)
    assert reasons
    assert "header_type" not in [finding.kind for finding in findings]


@pytest.mark.parametrize("kind", ["composition", "ref"])
@pytest.mark.parametrize("depth,complete", [(63, True), (64, False)])
def test_header_composition_depth_boundary(kind: str, depth: int, complete: bool) -> None:
    prop: dict[str, object] = {"type": "string", "x-mcp-header": "Authorization"}
    definitions: dict[str, object] = {}
    for index in range(depth):
        if kind == "composition":
            prop = {"allOf": [prop]}
        else:
            definitions[f"r{index}"] = prop
            prop = {"$ref": f"#/$defs/r{index}"}
    tool = ToolInfo(name="fixture", input_schema={"properties": {"api_token": prop}, "$defs": definitions})
    reasons: list[str] = []
    findings = scan_tool_schema(tool, incomplete_reasons=reasons)
    assert ("credential_header" in [finding.kind for finding in findings]) is complete
    assert bool(reasons) is not complete


def test_repeated_composition_refs_obey_work_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_audit import schema_rules

    monkeypatch.setattr(schema_rules, "_MAX_SCHEMA_NODES", 20)
    definitions: dict[str, object] = {"leaf": {"type": "string", "x-mcp-header": "X-Value"}}
    prop: dict[str, object] = {"$ref": "#/$defs/leaf"}
    for index in range(5):
        definitions[f"r{index}"] = prop
        prop = {"anyOf": [{"$ref": f"#/$defs/r{index}"}, {"$ref": f"#/$defs/r{index}"}]}
    reasons: list[str] = []
    scan_tool_schema(
        ToolInfo(name="fixture", input_schema={"properties": {"value": prop}, "$defs": definitions}),
        incomplete_reasons=reasons,
    )
    assert reasons


@pytest.mark.parametrize(
    "branches,kind",
    [
        ([{"type": "number"}, {"type": "integer"}], None),
        ([True, {"type": "string"}], None),
        ([False, {"type": "string"}], "header_type"),
        ([{"type": ["string", "object"]}, {"type": "string"}], None),
    ],
)
def test_allof_type_intersection(branches: list[object], kind: str | None) -> None:
    tool = ToolInfo(
        name="fixture",
        input_schema={"properties": {"value": {"allOf": branches, "x-mcp-header": "X-Value"}}},
    )
    reasons: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)] == (
        [kind] if kind else []
    )
    assert reasons == []


@pytest.mark.parametrize("schema", [{"anyOf": []}, {"oneOf": [None]}, {"$dynamicRef": "#value"}])
def test_unresolved_root_composition_records_incomplete_coverage(schema: dict[str, object]) -> None:
    reasons: list[str] = []
    assert scan_tool_schema(ToolInfo(name="fixture", input_schema=schema), incomplete_reasons=reasons) == []
    assert reasons


def test_external_root_reference_records_incomplete_header_coverage() -> None:
    tool = ToolInfo(name="fixture", input_schema={"$ref": "https://schemas.example.test/value"})
    reasons: list[str] = []
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)] == [
        "external_ref"
    ]
    assert reasons == ["x-mcp-header use could not be resolved for a property"]


def test_unused_composed_definition_does_not_create_credential_findings() -> None:
    schema = {
        "$defs": {"unused": {"anyOf": [{"type": "string", "x-mcp-header": "Authorization"}]}},
        "properties": {"api_token": {"type": "string"}},
    }
    reasons: list[str] = []
    tool = ToolInfo.model_validate({"name": "fixture", "input_schema": schema})
    assert [finding.kind for finding in scan_tool_schema(tool, incomplete_reasons=reasons)] == [
        "header_unreachable"
    ]
    assert reasons == []
