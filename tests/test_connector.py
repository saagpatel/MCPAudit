"""Tests for ServerConnector — unit and integration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_audit.connector import ServerConnector
from mcp_audit.models import ClientType, Confidence, PermissionCategory, ServerConfig
from tests.conftest import make_server_config

MOCK_SERVER = str(Path(__file__).parent / "fixtures" / "mock_server.py")


# ---------------------------------------------------------------------------
# Unit tests — no network / process spawning
# ---------------------------------------------------------------------------


class TestConvertAnnotations:
    def test_maps_camel_to_snake_case(self) -> None:
        from mcp.types import ToolAnnotations as SdkAnn

        sdk_ann = SdkAnn(
            title="My Tool",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
        result = ServerConnector._convert_annotations(sdk_ann)
        assert result.title == "My Tool"
        assert result.read_only_hint is True
        assert result.destructive_hint is False
        assert result.idempotent_hint is True
        assert result.open_world_hint is False

    def test_none_annotations_remain_none(self) -> None:
        from mcp.types import ToolAnnotations as SdkAnn

        sdk_ann = SdkAnn()
        result = ServerConnector._convert_annotations(sdk_ann)
        assert result.read_only_hint is None
        assert result.destructive_hint is None


class TestConvertTool:
    def test_handles_missing_description(self) -> None:
        from mcp.types import Tool as SdkTool

        sdk_tool = SdkTool(name="mytool", inputSchema={})
        result = ServerConnector._convert_tool(sdk_tool)
        assert result.name == "mytool"
        assert result.description is None
        assert result.annotations is None

    def test_converts_input_schema(self) -> None:
        from mcp.types import Tool as SdkTool

        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        sdk_tool = SdkTool(name="read_file", inputSchema=schema)
        result = ServerConnector._convert_tool(sdk_tool)
        assert result.input_schema == schema


class TestSkipConnectAudit:
    def test_filesystem_command_infers_file_permissions(self) -> None:
        config = make_server_config(
            name="fs",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        assert audit.connection_status == "skipped"
        cats = {f.category for f in audit.permissions}
        assert PermissionCategory.FILE_READ in cats
        assert PermissionCategory.FILE_WRITE in cats

    def test_env_key_with_token_implies_network(self) -> None:
        config = make_server_config(
            name="gh",
            command="node",
            args=["server.js"],
            env_keys=["GITHUB_TOKEN"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        cats = {f.category for f in audit.permissions}
        assert PermissionCategory.NETWORK in cats

    def test_env_key_with_api_key_implies_network(self) -> None:
        config = make_server_config(name="svc", env_keys=["OPENAI_API_KEY"])
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        cats = {f.category for f in audit.permissions}
        assert PermissionCategory.NETWORK in cats

    def test_unknown_server_returns_empty_permissions(self) -> None:
        config = make_server_config(name="unknown", command="python", args=["custom_server.py"])
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        # No credential env keys, no known pattern → empty
        assert audit.connection_status == "skipped"

    def test_all_skip_findings_are_low_confidence(self) -> None:
        config = make_server_config(
            name="fs",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        assert all(f.confidence == Confidence.LOW for f in audit.permissions)


# ---------------------------------------------------------------------------
# Integration tests — spawns mock server subprocess
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_connects_to_mock_stdio_server() -> None:
    config = ServerConfig(
        name="mock",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=sys.executable,
        args=[MOCK_SERVER],
    )
    connector = ServerConnector(timeout=15.0)
    audit = await connector.connect(config)
    assert audit.connection_status == "connected"
    assert len(audit.tools) == 3
    tool_names = {t.name for t in audit.tools}
    assert tool_names == {"read_file", "write_file", "execute_command"}


@pytest.mark.anyio
async def test_mock_server_tools_have_correct_annotations() -> None:
    config = ServerConfig(
        name="mock",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=sys.executable,
        args=[MOCK_SERVER],
    )
    connector = ServerConnector(timeout=15.0)
    audit = await connector.connect(config)
    read_tool = next(t for t in audit.tools if t.name == "read_file")
    assert read_tool.annotations is not None
    assert read_tool.annotations.read_only_hint is True
    assert read_tool.annotations.destructive_hint is False


@pytest.mark.anyio
async def test_annotation_coverage_computed() -> None:
    config = ServerConfig(
        name="mock",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=sys.executable,
        args=[MOCK_SERVER],
    )
    connector = ServerConnector(timeout=15.0)
    audit = await connector.connect(config)
    # 1 of 3 tools has annotations → coverage = 1/3 ≈ 0.33
    assert 0.0 < audit.annotation_coverage <= 1.0


@pytest.mark.anyio
async def test_timeout_returns_timeout_status() -> None:
    config = ServerConfig(
        name="slow",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=sys.executable,
        args=["-c", "import time; time.sleep(60)"],
    )
    connector = ServerConnector(timeout=1.0)
    audit = await connector.connect(config)
    assert audit.connection_status in ("timeout", "failed")


@pytest.mark.anyio
async def test_missing_command_returns_failed() -> None:
    config = ServerConfig(
        name="bad",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=None,
    )
    connector = ServerConnector(timeout=5.0)
    audit = await connector.connect(config)
    assert audit.connection_status == "failed"
    assert audit.connection_error is not None
