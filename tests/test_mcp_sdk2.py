"""Regression coverage for the MCP SDK 2 public surfaces MCPAudit uses."""

from __future__ import annotations

import importlib
import json

import pytest
from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, Prompt, PromptArgument, Resource, Tool, ToolAnnotations

from mcp_audit.connector import ServerConnector
from mcp_audit.server import _build_mcp_server
from tests.conftest import make_server_config

EXPECTED_TOOL_NAMES = {
    "scan_mcp_servers",
    "get_high_risk_servers",
    "check_server",
    "get_injection_findings",
    "get_ssrf_findings",
    "get_trifecta_findings",
    "get_shadowing_findings",
    "get_escalation_findings",
    "get_provenance_findings",
    "get_integrity_findings",
    "get_package_verify_findings",
    "get_artifact_verify_findings",
    "list_discovered_servers",
}


def test_sdk2_public_client_and_server_exports() -> None:
    assert Client.__name__ == "Client"
    assert MCPServer.__name__ == "MCPServer"
    assert issubclass(ToolError, Exception)


def test_v1_only_surfaces_are_gone() -> None:
    with pytest.raises(ModuleNotFoundError, match="MCPServer"):
        importlib.import_module("mcp.server.fastmcp")

    server_module = importlib.import_module("mcp.server")
    assert not hasattr(server_module, "FastMCP")

    http_module = importlib.import_module("mcp.client.streamable_http")
    assert not hasattr(http_module, "streamablehttp_client")


def test_tool_wire_types_use_snake_case_fields() -> None:
    tool = Tool(
        name="read_file",
        description="Read a file.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
    )
    converted = ServerConnector._convert_tool(tool)
    assert converted.name == "read_file"
    assert converted.input_schema == {"type": "object", "properties": {"path": {"type": "string"}}}
    assert converted.annotations is not None
    assert converted.annotations.read_only_hint is True
    assert converted.annotations.destructive_hint is False


def test_prompt_and_resource_wire_types_use_snake_case_fields() -> None:
    prompt = Prompt(
        name="summarize_file",
        description="Summarize a file.",
        arguments=[PromptArgument(name="path", required=True)],
    )
    resource = Resource(
        uri="file:///tmp/example.txt",
        name="example",
        description="Example file.",
        mime_type="text/plain",
    )
    converted_prompt = ServerConnector._convert_prompt(prompt)
    converted_resource = ServerConnector._convert_resource(resource)
    assert converted_prompt.arguments == ["path"]
    assert converted_resource.uri == "file:///tmp/example.txt"
    assert converted_resource.mime_type == "text/plain"


def test_stdio_spawn_contract_keeps_env_none() -> None:
    params = StdioServerParameters(command="python", args=["server.py"], env=None)
    assert params.env is None


@pytest.mark.anyio
async def test_mcpserver_call_tool_returns_call_tool_result() -> None:
    app = MCPServer(name="sdk2-probe")

    @app.tool()
    def ping() -> str:
        """Return a JSON object as text."""
        return json.dumps({"ok": True})

    result = await app.call_tool("ping", {})
    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    structured = result.structured_content
    assert isinstance(structured, dict)
    assert json.loads(structured["result"]) == {"ok": True}


@pytest.mark.anyio
async def test_mcpserver_unknown_tool_raises_tool_error() -> None:
    app = MCPServer(name="sdk2-probe")
    with pytest.raises(ToolError):
        await app.call_tool("missing", {})


@pytest.mark.anyio
async def test_audit_server_is_mcpserver_and_exposes_stable_tool_names() -> None:
    app = _build_mcp_server()
    assert isinstance(app, MCPServer)
    tools = await app.list_tools()
    assert {tool.name for tool in tools} == EXPECTED_TOOL_NAMES


@pytest.mark.anyio
async def test_audit_tool_result_preserves_structured_result_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mcp_audit.server.discover_all_configs",
        lambda clients: [make_server_config(name="a")],
    )
    result = await _build_mcp_server().call_tool("list_discovered_servers", {})

    assert result.is_error is False
    assert isinstance(result.structured_content, dict)
    assert json.loads(result.structured_content["result"]) == [
        {"name": "a", "client": "claude_code", "transport": "stdio"}
    ]


@pytest.mark.anyio
async def test_skip_connect_still_does_not_construct_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_client(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("skip-connect must not construct mcp.Client")

    monkeypatch.setattr("mcp_audit.connector.Client", fail_client)
    audit = ServerConnector().skip_connect_audit(make_server_config(name="local", command="python"))
    assert audit.connection_status == "skipped"
