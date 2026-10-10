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
