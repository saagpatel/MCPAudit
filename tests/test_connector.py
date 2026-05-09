"""Tests for ServerConnector — unit and integration."""

from __future__ import annotations

import os
import signal
import sys
import textwrap
import time
from pathlib import Path

import pytest

from mcp_audit.connector import ServerConnector
from mcp_audit.models import ClientType, Confidence, PermissionCategory, ServerConfig, TransportType
from tests.conftest import make_server_config

MOCK_SERVER = str(Path(__file__).parent / "fixtures" / "mock_server.py")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_process_exit(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return True
        time.sleep(0.05)
    return not _process_exists(pid)


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


class TestConvertCapabilities:
    def test_converts_prompt_arguments(self) -> None:
        from mcp.types import Prompt, PromptArgument

        sdk_prompt = Prompt(
            name="summarize_file",
            description="Summarize a file.",
            arguments=[PromptArgument(name="path", required=True)],
        )
        result = ServerConnector._convert_prompt(sdk_prompt)
        assert result.name == "summarize_file"
        assert result.description == "Summarize a file."
        assert result.arguments == ["path"]

    def test_converts_resource_metadata(self) -> None:
        from mcp.types import Resource

        sdk_resource = Resource(
            uri="file:///tmp/example.txt",
            name="example",
            description="Example file.",
            mimeType="text/plain",
        )
        result = ServerConnector._convert_resource(sdk_resource)
        assert result.uri == "file:///tmp/example.txt"
        assert result.name == "example"
        assert result.mime_type == "text/plain"


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
        network = next(f for f in audit.permissions if f.category == PermissionCategory.NETWORK)
        assert "env key" in " ".join(network.evidence)

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

    def test_http_transport_implies_network_without_connecting(self) -> None:
        config = make_server_config(
            name="remote",
            transport=TransportType.HTTP,
            url="https://example.com/mcp",
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        network = next(f for f in audit.permissions if f.category == PermissionCategory.NETWORK)
        assert "http transport" in " ".join(network.evidence)

    def test_shell_wrapper_implies_shell_execution(self) -> None:
        config = make_server_config(
            name="shell",
            command="bash",
            args=["-c", "python server.py"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        shell = next(f for f in audit.permissions if f.category == PermissionCategory.SHELL_EXEC)
        assert "shell wrapper" in " ".join(shell.evidence)

    def test_windows_shell_wrapper_path_implies_shell_execution(self) -> None:
        config = make_server_config(
            name="shell",
            command="C:\\Windows\\System32\\cmd.exe",
            args=["/c", "python server.py"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        shell = next(f for f in audit.permissions if f.category == PermissionCategory.SHELL_EXEC)
        assert "cmd.exe" in " ".join(shell.evidence)

    def test_remote_url_in_args_implies_network(self) -> None:
        config = make_server_config(
            name="remote-arg",
            command="node",
            args=["server.js", "--endpoint", "https://example.com/mcp"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        network = next(f for f in audit.permissions if f.category == PermissionCategory.NETWORK)
        assert "remote URL" in " ".join(network.evidence)

    def test_package_runner_implies_network(self) -> None:
        config = make_server_config(
            name="pkg",
            command="npx",
            args=["-y", "@example/server"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        network = next(f for f in audit.permissions if f.category == PermissionCategory.NETWORK)
        assert "package runner" in " ".join(network.evidence)

    def test_destructive_shell_pattern_is_flagged(self) -> None:
        config = make_server_config(
            name="danger",
            command="bash",
            args=["-c", "rm " + "-rf /tmp/demo"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        cats = {f.category for f in audit.permissions}
        assert PermissionCategory.SHELL_EXEC in cats
        assert PermissionCategory.DESTRUCTIVE in cats

    def test_skip_connect_deduplicates_category_with_multiple_evidence(self) -> None:
        config = make_server_config(
            name="remote",
            transport=TransportType.HTTP,
            url="https://example.com/mcp",
            env_keys=["API_KEY"],
        )
        connector = ServerConnector()
        audit = connector.skip_connect_audit(config)
        network_findings = [f for f in audit.permissions if f.category == PermissionCategory.NETWORK]
        assert len(network_findings) == 1
        assert len(network_findings[0].evidence) >= 2


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
    assert [prompt.name for prompt in audit.prompts] == ["summarize_file"]
    assert [resource.name for resource in audit.resources] == ["example"]


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
async def test_timeout_cleans_up_stdio_process(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid.txt"
    terminated_file = tmp_path / "terminated.txt"
    server_script = tmp_path / "slow_server.py"
    server_script.write_text(
        textwrap.dedent(
            """
            from __future__ import annotations

            import os
            import signal
            import sys
            import time
            from pathlib import Path

            pid_file = Path(sys.argv[1])
            terminated_file = Path(sys.argv[2])
            pid_file.write_text(str(os.getpid()))

            def handle_stop(_signum: int, _frame: object) -> None:
                terminated_file.write_text("terminated")
                raise SystemExit(0)

            signal.signal(signal.SIGTERM, handle_stop)
            signal.signal(signal.SIGINT, handle_stop)

            while True:
                time.sleep(0.1)
            """
        )
    )

    config = ServerConfig(
        name="slow",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=sys.executable,
        args=[str(server_script), str(pid_file), str(terminated_file)],
    )
    connector = ServerConnector(timeout=0.2)

    try:
        audit = await connector.connect(config)
        assert audit.connection_status == "timeout"

        assert pid_file.exists()
        pid = int(pid_file.read_text())
        assert terminated_file.exists() or _wait_for_process_exit(pid)
    finally:
        if pid_file.exists():
            pid = int(pid_file.read_text())
            if _process_exists(pid):
                os.kill(pid, signal.SIGKILL)


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


@pytest.mark.anyio
async def test_http_without_url_fails_cleanly() -> None:
    config = ServerConfig(
        name="bad-http",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        transport=TransportType.HTTP,
        url=None,
    )
    connector = ServerConnector(timeout=5.0)

    audit = await connector.connect(config)
    assert audit.connection_status == "failed"
    assert audit.connection_error is not None
    assert "no URL" in audit.connection_error


@pytest.mark.anyio
async def test_connection_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ServerConfig(
        name="bad",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command="python",
    )
    connector = ServerConnector(timeout=5.0)

    async def fail_connect(_config: ServerConfig) -> list[object]:
        raise RuntimeError("failed with token=abc123")

    monkeypatch.setattr(connector, "_connect_stdio", fail_connect)
    audit = await connector.connect(config)
    assert audit.connection_status == "failed"
    assert audit.connection_error == "failed with token=<redacted>"
