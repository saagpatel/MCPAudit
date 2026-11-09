import json
from pathlib import Path

import pytest

from mcp_audit.api import parse_config
from mcp_audit.models import ClientType, ServerConfig, ToolInfo, TransportType
from mcp_audit.pin_signing import generate_keypair
from mcp_audit.pinning import PinStore
from redteam.chains.pairs import load_config
from redteam.surface import ServerSurface, SurfaceConfig, SurfaceTool


def _server_config() -> ServerConfig:
    return ServerConfig(
        name="filesystem",
        client=ClientType.CLAUDE_CODE,
        config_path="synthetic-config.toml",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
        env_keys=["TOKEN"],
        transport=TransportType.STDIO,
    )


def _surface(tool_name: str) -> ServerSurface:
    return ServerSurface(server_name="filesystem", source="fixture", tools=[SurfaceTool(name=tool_name)])


def test_codex_toml_uses_mcp_parser_and_keeps_only_environment_key_names(tmp_path: Path) -> None:
    config_path = tmp_path / "codex.toml"
    config_path.write_text(
        "[mcp_servers.filesystem]\n"
        'command = "npx"\n'
        'args = ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"]\n'
        "[mcp_servers.filesystem.env]\n"
        'TOKEN = "synthetic-secret-value"\n',
        encoding="utf-8",
    )

    server = load_config(config_path)[0]

    assert server.source == "catalog"
    assert server.env_keys == ("TOKEN",)
    assert server.surface is not None
    assert "synthetic-secret-value" not in repr(server)


def test_pin_surface_requires_launch_identity_match(tmp_path: Path) -> None:
    config = _server_config()
    trusted_keys = tmp_path / "trusted-keys.yaml"
    key = generate_keypair(tmp_path / "keys", trusted_keys)
    store = PinStore(
        tmp_path / ".mcp-audit-pins.yaml",
        signing_key=key.private_key_path,
        trusted_keys_path=trusted_keys,
    )
    store.pin_server("historical-filesystem", [ToolInfo(name="pinned_tool")], config)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                        "env": {"TOKEN": "synthetic-secret-value"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    pinned = load_config(config_path, pins_dir=tmp_path)[0]
    assert pinned.source == "pin"
    assert pinned.surface is not None
    assert [tool.name for tool in pinned.surface.tools] == ["pinned_tool"]
    assert pinned.surface.provenance == (
        "signature-verified historical pin matching launch identity; current surface unverified"
    )
    assert pinned.env_keys == ("TOKEN",)

    changed = parse_config(
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/other"],
                }
            }
        }
    )
    mismatched_config = tmp_path / "changed.json"
    mismatched_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": changed[0].command,
                        "args": changed[0].args,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    mismatched = load_config(mismatched_config, pins_dir=tmp_path)[0]
    assert mismatched.source == "catalog"
    assert mismatched.surface is not None
    assert all(tool.name != "pinned_tool" for tool in mismatched.surface.tools)


def test_explicit_surface_precedes_pin_and_catalog(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "surface.json").write_text(_surface("explicit_tool").to_json(), encoding="utf-8")
    (tmp_path / "surfaces.json").write_text(json.dumps({"filesystem": "surface.json"}), encoding="utf-8")
    store = PinStore(
        tmp_path / ".mcp-audit-pins.yaml",
        signing_key=tmp_path / "signing-key.pem",
        trusted_keys_path=tmp_path / "trusted-keys.yaml",
        unsigned=True,
    )
    store.pin_server("filesystem", [ToolInfo(name="pinned_tool")], _server_config())

    server = load_config(config_path, tmp_path / "surfaces.json", pins_dir=tmp_path)[0]

    assert server.source == "explicit"
    assert server.surface is not None
    assert [tool.name for tool in server.surface.tools] == ["explicit_tool"]


@pytest.mark.parametrize(
    "surface",
    [
        ServerSurface(server_name="other", source="fixture", tools=[SurfaceTool(name="wrong_name")]),
        ServerSurface(
            server_name="filesystem",
            source="fixture",
            config=SurfaceConfig(command="different-launcher", args=["different-package"]),
            tools=[SurfaceTool(name="wrong_launch")],
        ),
        ServerSurface(
            server_name="filesystem",
            source="fixture",
            config=SurfaceConfig(command="npx", args=[]),
            tools=[SurfaceTool(name="partial_launch")],
        ),
    ],
)
def test_explicit_surface_must_match_mapped_name_and_declared_launch(
    tmp_path: Path, surface: ServerSurface
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "surface.json").write_text(surface.to_json(), encoding="utf-8")
    (tmp_path / "surfaces.json").write_text(json.dumps({"filesystem": "surface.json"}), encoding="utf-8")

    resolved = load_config(config_path, tmp_path / "surfaces.json")[0]

    assert resolved.source == "catalog"
    assert resolved.surface is not None
    assert all(tool.name not in {"wrong_name", "wrong_launch"} for tool in resolved.surface.tools)


def test_unsigned_pin_is_not_a_known_chain_surface(tmp_path: Path) -> None:
    store = PinStore(
        tmp_path / ".mcp-audit-pins.yaml",
        signing_key=tmp_path / "signing-key.pem",
        trusted_keys_path=tmp_path / "trusted-keys.yaml",
        unsigned=True,
    )
    store.pin_server("filesystem", [ToolInfo(name="unsigned_tool")], _server_config())
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                        "env": {"TOKEN": "synthetic-secret-value"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = load_config(config_path, pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "withheld" in resolved.reason


def test_withheld_same_name_pin_does_not_fall_back_to_catalog(tmp_path: Path) -> None:
    old_baseline = (
        "servers:\n  filesystem:\n    tools:\n      old_tool:\n"
        "        pin_schema: 1\n        hash: sha256:old\n"
    )
    (tmp_path / ".mcp-audit-pins.yaml").write_text(old_baseline, encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    server = load_config(config_path, pins_dir=tmp_path)[0]

    assert server.source == "unknown"
    assert server.tool_surface == "UNKNOWN"
    assert server.surface is None
    assert server.reason is not None and "withheld" in server.reason


def test_default_pin_store_is_never_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"filesystem": {"command": "npx", "args": []}}}),
        encoding="utf-8",
    )

    def unexpected_pin_read(*args: object, **kwargs: object) -> PinStore:
        raise AssertionError("PinStore must only be read when --pins is explicitly supplied")

    monkeypatch.setattr("redteam.chains.pairs.PinStore", unexpected_pin_read)
    assert load_config(config_path)[0].tool_surface == "UNKNOWN"


def test_malformed_explicit_surfaces_mapping_is_a_value_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"mcpServers": {"filesystem": {"command": "npx"}}}))
    mapping_path = tmp_path / "surfaces.json"
    mapping_path.write_text('["surface.json"]', encoding="utf-8")

    with pytest.raises(ValueError, match="surfaces mapping"):
        load_config(config_path, mapping_path)


def test_malformed_explicit_pin_store_yields_unknown(tmp_path: Path) -> None:
    (tmp_path / ".mcp-audit-pins.yaml").write_text("servers: [\n", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    server = load_config(config_path, pins_dir=tmp_path)[0]

    assert server.tool_surface == "UNKNOWN"
    assert server.surface is None


def test_conflicting_pins_for_same_launch_identity_yield_unknown(tmp_path: Path) -> None:
    trusted_keys = tmp_path / "trusted-keys.yaml"
    key = generate_keypair(tmp_path / "keys", trusted_keys)
    store = PinStore(
        tmp_path / ".mcp-audit-pins.yaml",
        signing_key=key.private_key_path,
        trusted_keys_path=trusted_keys,
    )
    config = _server_config()
    store.pin_server("first-name", [ToolInfo(name="first_tool")], config)
    store.pin_server("second-name", [ToolInfo(name="second_tool")], config)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                        "env": {"TOKEN": "synthetic-secret-value"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    server = load_config(config_path, pins_dir=tmp_path)[0]

    assert server.tool_surface == "UNKNOWN"
    assert server.surface is None
