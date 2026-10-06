"""Tests for ServerConnector — unit and integration."""

from __future__ import annotations

import logging
import os
import signal
import sys
import textwrap
import threading
import time
from io import StringIO
from pathlib import Path

import anyio
import pytest

from mcp_audit.connector import ServerConnector
from mcp_audit.models import ClientType, Confidence, PermissionCategory, ServerConfig, TransportType
from tests.conftest import make_server_config

MOCK_SERVER = str(Path(__file__).parent / "fixtures" / "mock_server.py")


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["complete", "timeout", "cancel", "fail", "quiet"])
async def test_stdio_stderr_is_bounded_sanitized_and_cleaned_up(
    mode: str, capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    # Warm AnyIO's unrelated reusable worker before measuring session cleanup.
    await anyio.to_thread.run_sync(lambda: None)
    baseline_threads = set(threading.enumerate())
    fd_root = Path("/dev/fd") if Path("/dev/fd").exists() else Path("/proc/self/fd")
    baseline_fds = len(list(fd_root.iterdir())) if fd_root.exists() else None
    args = ["-m", "tests.fixtures.noisy_stderr_server"]
    if mode in ("timeout", "cancel"):
        args.append("hang")
    elif mode == "fail":
        args.append("fail")
    config = make_server_config(name="stderr-fixture", command=sys.executable, args=args)
    connector = ServerConnector(timeout=0.5 if mode == "timeout" else 5)
    caplog.set_level(logging.INFO if mode == "quiet" else logging.DEBUG, logger="mcp_audit.connector")
    if mode == "cancel":
        with anyio.move_on_after(0.5) as scope:
            await connector.connect(config)
        assert scope.cancelled_caught
    else:
        audit = await connector.connect(config)
        expected_status = {
            "complete": "connected",
            "quiet": "connected",
            "fail": "failed",
            "timeout": "timeout",
        }
        assert audit.connection_status == expected_status[mode]
    captured = capfd.readouterr()
    assert "stderr-noise" not in captured.err
    assert "stderr-tail" not in captured.err
    assert "\x1b" not in captured.err
    records = [r.getMessage() for r in caplog.records if "stderr tail:" in r.getMessage()]
    if mode == "quiet":
        assert records == []
    else:
        assert len(records) == 1
        assert "stderr tail: …[truncated] stderr-tail[/bold]\nBearer <redacted>\n" in records[0]
        assert "stderr-tail[/bold]" in records[0]
        assert "Bearer <redacted>" in records[0]
        assert "fixture-sensitive-marker" not in records[0]
        assert "\x1b" not in records[0] and "\x07" not in records[0]
        assert len(records[0]) <= 4096 + 100
    assert set(threading.enumerate()) == baseline_threads
    if baseline_fds is not None:
        assert len(list(fd_root.iterdir())) == baseline_fds


@pytest.mark.anyio
@pytest.mark.parametrize("prefix", ["bearer", "token"])
@pytest.mark.parametrize("newline", [False, True])
async def test_stdio_stderr_truncation_discards_unanchored_secrets(
    prefix: str, newline: bool, caplog: pytest.LogCaptureFixture
) -> None:
    args = ["-m", "tests.fixtures.noisy_stderr_server", f"boundary-{prefix}"]
    if newline:
        args.append("newline")
    config = make_server_config(name="stderr-fixture", command=sys.executable, args=args)
    caplog.set_level(logging.DEBUG, logger="mcp_audit.connector")
    audit = await ServerConnector(timeout=5).connect(config)
    assert audit.connection_status == "connected"
    assert "fixture-boundary-marker" not in caplog.text
    records = [r.getMessage() for r in caplog.records if "stderr tail:" in r.getMessage()]
    suffix = "stderr-whole-tail\n" if newline else "<stderr truncated; last record exceeded 4 KiB>"
    assert records == [f"Server stderr-fixture stderr tail: …[truncated] {suffix}"]


@pytest.mark.anyio
async def test_stdio_short_stderr_preserves_redacted_line(caplog: pytest.LogCaptureFixture) -> None:
    config = make_server_config(
        name="stderr-fixture",
        command=sys.executable,
        args=["-m", "tests.fixtures.noisy_stderr_server", "short"],
    )
    caplog.set_level(logging.DEBUG, logger="mcp_audit.connector")
    audit = await ServerConnector(timeout=5).connect(config)
    assert audit.connection_status == "connected"
    records = [r.getMessage() for r in caplog.records if "stderr tail:" in r.getMessage()]
    assert records == ["Server stderr-fixture stderr tail: before token=<redacted> after\n"]
    assert "abc123" not in caplog.text


def test_stderr_capture_closes_reader_even_when_a_writer_is_retained() -> None:
    from mcp_audit.connector import _capture_stderr

    baseline = set(threading.enumerate())
    retained_fd: int | None = None
    try:
        with _capture_stderr("fixture") as errlog:
            retained_fd = os.dup(errlog.fileno())
            os.write(retained_fd, b"fixture-tail")
        assert set(threading.enumerate()) == baseline
        with pytest.raises(BrokenPipeError):
            os.write(retained_fd, b"closed-reader")
    finally:
        if retained_fd is not None:
            os.close(retained_fd)


@pytest.mark.parametrize("payload", ["\x1b[2J", "\x1b]0;pwned\x07", "\x9b31m"])
def test_sse_warning_and_traceback_controls_are_stripped(payload: str) -> None:
    from mcp_audit.connector import _SseLogFilter

    record = logging.LogRecord("mcp.client.sse", logging.WARNING, "fixture", 1, "%s", (payload,), None)
    record.exc_text = payload
    record.stack_info = payload
    assert _SseLogFilter().filter(record)
    output = logging.Formatter().format(record)
    assert "\x1b" not in output and "\x07" not in output and "\x9b" not in output


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
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
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

        sdk_tool = SdkTool(name="mytool", input_schema={})
        result = ServerConnector._convert_tool(sdk_tool)
        assert result.name == "mytool"
        assert result.description is None
        assert result.annotations is None

    def test_converts_input_schema(self) -> None:
        from mcp.types import Tool as SdkTool

        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        sdk_tool = SdkTool(name="read_file", input_schema=schema)
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
            mime_type="text/plain",
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
async def test_unadvertised_capabilities_still_list_tools(caplog: pytest.LogCaptureFixture) -> None:
    # An ordinary scan reports what a server serves, not what it advertised.
    fixture = str(Path(__file__).parent / "fixtures" / "canary_surfaces_server.py")
    config = make_server_config(command=sys.executable, args=[fixture, "noadvert"])
    with caplog.at_level(logging.DEBUG, logger="mcp_audit.connector"):
        audit = await ServerConnector(timeout=15.0).connect(config)
    assert audit.connection_status == "connected"
    assert [tool.name for tool in audit.tools] == ["status0"]
    assert audit.prompts == [] and audit.resources == []
    assert audit.canary is None
    assert "prompt listing unavailable" in caplog.text
    assert "resource listing unavailable" in caplog.text


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
    connector = ServerConnector(timeout=1.0)

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


class _SpawnAborted(Exception):
    """Raised by the fake Client so no real process is ever spawned."""


async def test_connect_stdio_never_hands_spawned_server_an_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin the load-bearing safety property of connected scans: the spawned
    server gets env=None, which makes the mcp SDK use its curated safe default
    environment — never the operator's os.environ and never the credentials the
    config declares for the server. A regression here would inject real secrets
    into a process this tool exists to distrust.
    """
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, server: object, **_kwargs: object) -> None:
            raise _SpawnAborted

    def fake_stdio_client(server: object, *, errlog: object) -> object:
        captured["env"] = getattr(server, "env", "missing")
        return object()

    monkeypatch.setattr("mcp_audit.connector.Client", FakeClient)
    monkeypatch.setattr("mcp_audit.connector.stdio_client", fake_stdio_client)

    connector = ServerConnector(timeout=1.0)
    config = make_server_config(name="srv", env_keys=["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"])

    with pytest.raises(_SpawnAborted):
        await connector._connect_stdio(config)

    assert "env" in captured
    assert captured["env"] is None


def _patch_client_and_sse(
    monkeypatch: pytest.MonkeyPatch,
    *,
    captured: dict[str, object],
    error: BaseException | None = None,
) -> object:
    """Capture Client construction and sse_client selection without opening a network."""
    sse_sentinel = object()

    def fake_sse_client(url: str, *_args: object, **_kwargs: object) -> object:
        captured["sse_called"] = True
        captured["sse_url"] = url
        return sse_sentinel

    class FakeClient:
        def __init__(self, server: object, **_kwargs: object) -> None:
            captured["client_server"] = server
            raise error if error is not None else _SpawnAborted("no network")

    monkeypatch.setattr("mcp_audit.connector.sse_client", fake_sse_client, raising=False)
    monkeypatch.setattr("mcp_audit.connector.Client", FakeClient)
    return sse_sentinel


@pytest.mark.anyio
async def test_sse_connect_uses_legacy_sse_transport_not_url_string(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: mcp 2.1.1 treats Client(str) as Streamable HTTP, so type:sse
    must pass sse_client(...) as Transport instead of the URL string.
    """
    captured: dict[str, object] = {}
    sse_sentinel = _patch_client_and_sse(monkeypatch, captured=captured)
    url = "https://user:s3cret-token@example.com/sse"
    config = ServerConfig(
        name="legacy-sse",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=None,
        transport=TransportType.SSE,
        url=url,
    )
    connector = ServerConnector(timeout=1.0)

    with caplog.at_level(logging.WARNING, logger="mcp_audit.connector"):
        audit = await connector.connect(config)

    assert captured.get("sse_called") is True
    assert captured.get("sse_url") == url
    assert captured.get("client_server") is sse_sentinel
    assert captured.get("client_server") != url
    assert "deprecated SSE transport" in caplog.text
    assert "StreamableHTTP" not in caplog.text
    assert "s3cret-token" not in caplog.text
    assert audit.connection_status == "failed"
    assert audit.connection_error is not None
    assert "s3cret-token" not in audit.connection_error
    assert "user:s3cret" not in audit.connection_error


@pytest.mark.anyio
async def test_http_connect_still_passes_url_string_for_streamable_http(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    captured: dict[str, object] = {}
    _patch_client_and_sse(monkeypatch, captured=captured)
    url = "https://example.com/mcp"
    config = ServerConfig(
        name="remote-http",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=None,
        transport=TransportType.HTTP,
        url=url,
    )
    connector = ServerConnector(timeout=1.0)

    with caplog.at_level(logging.WARNING, logger="mcp_audit.connector"):
        audit = await connector.connect(config)

    assert "sse_called" not in captured
    assert captured.get("client_server") == url
    assert isinstance(captured.get("client_server"), str)
    assert "deprecated SSE" not in caplog.text
    assert audit.connection_status == "failed"


@pytest.mark.anyio
async def test_sse_connection_error_redacts_url_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    _patch_client_and_sse(
        monkeypatch,
        captured=captured,
        error=RuntimeError("failed with token=abc123 at https://user:pass@example.com/sse"),
    )
    config = ServerConfig(
        name="legacy-sse",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        command=None,
        transport=TransportType.SSE,
        url="https://user:pass@example.com/sse",
    )
    connector = ServerConnector(timeout=1.0)
    audit = await connector.connect(config)

    assert audit.connection_status == "failed"
    assert audit.connection_error == "failed with token=<redacted> at https://<redacted>@example.com/sse"
    assert "abc123" not in (audit.connection_error or "")
    assert "user:pass" not in (audit.connection_error or "")


@pytest.mark.anyio
async def test_sse_without_url_fails_cleanly() -> None:
    config = ServerConfig(
        name="bad-sse",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/test_config.json",
        transport=TransportType.SSE,
        url=None,
    )
    connector = ServerConnector(timeout=5.0)

    audit = await connector.connect(config)
    assert audit.connection_status == "failed"
    assert audit.connection_error is not None
    assert "no URL" in audit.connection_error


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("scheme", "userinfo"),
    [("https", "user:password"), ("HTTPS", "user:password"), ("https", "user:password@tail")],
)
async def test_sse_sdk_logger_filters_wire_debug_and_redacts_endpoint_diagnostics(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, scheme: str, userinfo: str
) -> None:
    import httpx2
    from httpcore2._trace import Trace
    from mcp.client.sse import logger as sdk_logger

    from mcp_audit.connector import _SSE_LOGGER_NAMES

    transport_loggers = [logging.getLogger(name) for name in _SSE_LOGGER_NAMES]
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    for transport_logger in transport_loggers:
        monkeypatch.setattr(transport_logger, "filters", [])
        transport_logger.addHandler(handler)
    endpoint = (
        f"{scheme}://{userinfo}@example.com/messages?sessionId=live-session&opaque=live-value#live-fragment"
    )

    class FakeClient:
        def __init__(self, server: object, **_kwargs: object) -> None:
            sdk_logger.debug("Received endpoint URL: %s", endpoint)
            sdk_logger.debug("Sending client message: %s", {"secret": "wire-payload-secret"})
            sdk_logger.warning("SSE diagnostic remains available")
            sdk_logger.error("Endpoint origin does not match connection origin: %s", endpoint)
            try:
                raise RuntimeError(f"SSE request failed at {endpoint}")
            except RuntimeError:
                sdk_logger.exception("SSE fixture exception")
            raise _SpawnAborted("no network")

    monkeypatch.setattr("mcp_audit.connector.Client", FakeClient)
    config = make_server_config(transport=TransportType.SSE, url="https://example.com/sse")
    connector = ServerConnector(timeout=1.0)
    try:
        with caplog.at_level(logging.DEBUG):
            for _ in range(2):
                audit = await connector.connect(config)
                assert audit.connection_status == "failed"
            async with httpx2.AsyncClient(
                transport=httpx2.MockTransport(lambda request: httpx2.Response(200))
            ) as client:
                response = await client.post(endpoint)
                assert response.status_code == 200
            for name in _SSE_LOGGER_NAMES:
                if name.startswith("httpcore2."):
                    with Trace(
                        "receive_response_headers",
                        logging.getLogger(name),
                        kwargs={"headers": [(b"Authorization", b"Bearer wire-payload-secret")]},
                    ):
                        pass
        assert all(len(transport_logger.filters) == 1 for transport_logger in transport_loggers)
        for output in (stream.getvalue(), caplog.text):
            assert "SSE diagnostic remains available" in output
            assert "HTTP Request: POST" in output
            assert "Endpoint origin does not match connection origin" in output
            assert (
                f"RuntimeError: SSE request failed at {scheme}://<redacted>@example.com/messages?<redacted>"
                in output
            )
            for secret in (
                "user:password",
                "@tail",
                "live-session",
                "live-value",
                "live-fragment",
                "wire-payload-secret",
            ):
                assert secret not in output
        assert not any(
            record.levelno == logging.DEBUG for record in caplog.records if record.name in _SSE_LOGGER_NAMES
        )
    finally:
        for transport_logger in transport_loggers:
            transport_logger.removeHandler(handler)
