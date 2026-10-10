"""Shared pytest fixtures for mcp-audit tests."""

from pathlib import Path

import pytest

from mcp_audit.models import ClientType, ServerConfig, ToolAnnotations, ToolInfo, TransportType
from mcp_audit.pinning import PinStore


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--perf-profile",
        choices=("baseline", "p1-9", "p3-7", "p3-8"),
        default="baseline",
        help="Cumulative performance targets; promote the default as the planned fixes land.",
    )
    parser.addoption("--perf-output", type=Path, help="Directory for synthetic performance measurements.")


@pytest.fixture
def anyio_backend() -> str:
    """Use asyncio backend for all async tests."""
    return "asyncio"


@pytest.fixture(autouse=True)
def isolated_pin_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin tests must never read workstation signing keys or update its trust store."""
    from mcp_audit import pin_signing, pinning

    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", tmp_path / "keys" / "pin-signing.key")
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", tmp_path / "trusted-pin-keys.json")
    # Policy gates may open the default pin store; keep it off the workstation.
    monkeypatch.setattr(pinning, "DEFAULT_PIN_PATH", tmp_path / "default-pins.yaml")
    monkeypatch.delenv("MCP_AUDIT_PIN_KEY", raising=False)


@pytest.fixture(autouse=True)
def isolated_canary_pins(request: pytest.FixtureRequest) -> None:
    """Canary lanes must not read the workstation's saved pin snapshots."""
    if request.node.path.name not in {
        "test_agent_text.py",
        "test_canary.py",
        "test_canary_contract.py",
        "test_canary_identity.py",
        "test_coverage.py",
    }:
        return
    from mcp_audit import pinning

    tmp_path: Path = request.getfixturevalue("tmp_path")
    monkeypatch: pytest.MonkeyPatch = request.getfixturevalue("monkeypatch")

    class LocalPinStore(PinStore):
        def __init__(self, path: Path = tmp_path / "pins.yaml") -> None:
            super().__init__(path=path)

    monkeypatch.setattr(pinning, "PinStore", LocalPinStore)


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
