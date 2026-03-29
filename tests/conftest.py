"""Shared pytest fixtures for mcp-audit tests."""

from pathlib import Path

import pytest

from mcp_audit.models import ClientType, ServerConfig, ToolAnnotations, ToolInfo, TransportType


@pytest.fixture
def anyio_backend() -> str:
    """Use asyncio backend for all async tests."""
    return "asyncio"


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def mock_server_path() -> Path:
    return Path(__file__).parent / "fixtures" / "mock_server.py"


# ---------------------------------------------------------------------------
# Factory fixtures
# ---------------------------------------------------------------------------


def make_server_config(
    name: str = "test-server",
    client: ClientType = ClientType.CLAUDE_CODE,
    command: str | None = "npx",
    args: list[str] | None = None,
    env_keys: list[str] | None = None,
    transport: TransportType = TransportType.STDIO,
    url: str | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path="/tmp/test_config.json",
        command=command,
        args=args or [],
        env_keys=env_keys or [],
        transport=transport,
        url=url,
    )


def make_tool(
    name: str,
    description: str | None = None,
    input_schema: dict[str, object] | None = None,
    annotations: ToolAnnotations | None = None,
) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema=input_schema,
        annotations=annotations,
    )


@pytest.fixture
def server_config_factory() -> type:
    return make_server_config  # type: ignore[return-value]


@pytest.fixture
def tool_factory() -> type:
    return make_tool  # type: ignore[return-value]
