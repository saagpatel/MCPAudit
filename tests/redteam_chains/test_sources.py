import json
from pathlib import Path

import pytest
import yaml
from pydantic import TypeAdapter

from mcp_audit.api import parse_config
from mcp_audit.models import ClientType, ServerConfig, ToolInfo, TransportType
from mcp_audit.pin_signing import generate_keypair
from mcp_audit.pinning import PinStore
from redteam.chains.pairs import load_config, resolve_configs
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
    return ServerSurface(
        server_name="filesystem",
        source="fixture",
        config=SurfaceConfig(
            command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"]
        ),
        tools=[SurfaceTool(name=tool_name)],
    )


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

    assert resolved.source == "unknown"
    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "did not match" in resolved.reason


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


def _signed_store(tmp_path: Path) -> PinStore:
    trusted_keys = tmp_path / "trusted-keys.yaml"
    key = generate_keypair(tmp_path / "keys", trusted_keys)
    return PinStore(
        tmp_path / ".mcp-audit-pins.yaml",
        signing_key=key.private_key_path,
        trusted_keys_path=trusted_keys,
    )


@pytest.mark.parametrize(
    "damage", ["deleted-entry", "deleted-file", "tampered-manifest", "missing-manifest", "bad-signature"]
)
def test_signed_pin_damage_blocks_catalog_fallback(tmp_path: Path, damage: str) -> None:
    config = _server_config()
    store = _signed_store(tmp_path)
    store.pin_server(config.name, [ToolInfo(name="pinned_tool")], config)
    assert store.baseline_trusted(config.name)
    assert resolve_configs([config], pins_dir=tmp_path)[0].source == "pin"
    trusted_before = (tmp_path / "trusted-keys.yaml").read_bytes()
    document = TypeAdapter(dict[str, object]).validate_python(yaml.safe_load(store.path.read_text()))
    if damage == "deleted-entry":
        document["servers"] = {}
    elif damage == "tampered-manifest":
        manifest = TypeAdapter(dict[str, object]).validate_python(document["manifest"])
        manifest["sequence"] = 999
        document["manifest"] = manifest
    elif damage == "missing-manifest":
        del document["manifest"]
    elif damage == "bad-signature":
        servers = TypeAdapter(dict[str, dict[str, object]]).validate_python(document["servers"])
        servers[config.name]["signature"] = "invalid"
        document["servers"] = servers
    if damage == "deleted-file":
        store.path.unlink()
    else:
        store.path.write_text(yaml.safe_dump(document))

    resolved = resolve_configs([config], pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.source == "unknown"
    assert resolved.surface is None
    assert resolved.reason is not None and "withheld" in resolved.reason
    assert (tmp_path / "trusted-keys.yaml").read_bytes() == trusted_before
    assert resolve_configs([config])[0].source == "catalog"


def test_deleted_pin_remains_withheld_with_valid_replacement_manifest(tmp_path: Path) -> None:
    config = _server_config()
    store = _signed_store(tmp_path)
    # Replay a genuine, signed manifest from before this name was pinned. Only
    # the persisted signing expectation can detect the missing name here.
    store.pin_server("other", [ToolInfo(name="other_tool")], config)
    earlier = store.path.read_bytes()
    store.pin_server(config.name, [ToolInfo(name="pinned_tool")], config)
    store.path.write_bytes(earlier)

    resolved = resolve_configs([config], pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "withheld" in resolved.reason


def test_same_name_pin_identity_mismatch_blocks_catalog_and_matching_alias(tmp_path: Path) -> None:
    config = _server_config()
    store = _signed_store(tmp_path)
    store.pin_server("matching-alias", [ToolInfo(name="alias_tool")], config)
    old_config = config.model_copy(update={"args": ["old-launch"]})
    store.pin_server(config.name, [ToolInfo(name="old_tool")], old_config)

    resolved = resolve_configs([config], pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "withheld" in resolved.reason


def test_failed_alias_signature_blocks_catalog_fallback(tmp_path: Path) -> None:
    config = _server_config()
    store = _signed_store(tmp_path)
    store.pin_server("alias", [ToolInfo(name="pinned_tool")], config)
    document = TypeAdapter(dict[str, object]).validate_python(yaml.safe_load(store.path.read_text()))
    servers = TypeAdapter(dict[str, dict[str, object]]).validate_python(document["servers"])
    servers["alias"]["signature"] = "invalid"
    document["servers"] = servers
    store.path.write_text(yaml.safe_dump(document))

    resolved = resolve_configs([config], pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "withheld" in resolved.reason


def test_absent_unexpected_pin_allows_catalog_fallback(tmp_path: Path) -> None:
    assert resolve_configs([_server_config()], pins_dir=tmp_path)[0].source == "catalog"


def test_explicit_identity_failure_does_not_fall_back_to_matching_pin(tmp_path: Path) -> None:
    config = _server_config()
    store = _signed_store(tmp_path)
    store.pin_server(config.name, [ToolInfo(name="pinned_tool")], config)
    mismatched = _surface("explicit_tool").model_copy(update={"server_name": "wrong-name"})

    resolved = resolve_configs([config], {config.name: mismatched}, pins_dir=tmp_path)[0]

    assert resolved.tool_surface == "UNKNOWN"
    assert resolved.surface is None
    assert resolved.reason is not None and "did not match" in resolved.reason


@pytest.mark.parametrize("transport", [TransportType.HTTP, TransportType.SSE])
@pytest.mark.parametrize(
    ("declared_url", "matches"),
    [
        ("https://example.invalid/mcp", True),
        ("HTTPS://EXAMPLE.INVALID:443/mcp?token=other-secret#ignored", True),
        ("https://other.invalid/mcp", False),
        ("http://example.invalid/mcp", False),
        ("https://example.invalid:8443/mcp", False),
        ("https://example.invalid/other", False),
        ("https://example.invalid:bad/mcp", False),
        ("/mcp", False),
        (None, False),
    ],
)
def test_remote_explicit_surfaces_match_endpoint_identity(
    transport: TransportType, declared_url: str | None, matches: bool
) -> None:
    config = ServerConfig(
        name="remote",
        client=ClientType.CLAUDE_CODE,
        config_path="synthetic.json",
        transport=transport,
        url="https://example.invalid/mcp?token=synthetic-secret",
    )
    surface = ServerSurface(
        server_name=config.name,
        config=SurfaceConfig(transport=transport.value, url=declared_url),
        tools=[SurfaceTool(name="explicit_tool")],
        source="fixture",
    )

    resolved = resolve_configs([config], {config.name: surface})[0]

    assert resolved.tool_surface == ("KNOWN" if matches else "UNKNOWN")
    assert resolved.source == ("explicit" if matches else "unknown")
    assert "secret" not in (resolved.reason or "")


@pytest.mark.parametrize("transport", [TransportType.HTTP, TransportType.SSE])
def test_remote_identity_requires_declared_matching_transport(transport: TransportType) -> None:
    config = _server_config().model_copy(update={"transport": transport, "url": "http://example.invalid"})
    for declared_transport in ("stdio", "http" if transport == TransportType.SSE else "sse"):
        surface = _surface("explicit_tool")
        surface.config = SurfaceConfig.model_validate(
            {"transport": declared_transport, "url": config.url, "env_keys": ["TOKEN"]}
        )
        assert resolve_configs([config], {config.name: surface})[0].tool_surface == "UNKNOWN"
    # A stdio-looking command must not select a stdio catalog for a remote config.
    assert resolve_configs([config])[0].tool_surface == "UNKNOWN"


def test_remote_endpoint_default_port_and_empty_path_match() -> None:
    config = _server_config().model_copy(
        update={"transport": TransportType.HTTP, "url": "http://example.invalid"}
    )
    surface = _surface("explicit_tool")
    surface.config = SurfaceConfig(transport="http", url="HTTP://EXAMPLE.INVALID:80/", env_keys=["TOKEN"])
    assert resolve_configs([config], {config.name: surface})[0].source == "explicit"


@pytest.mark.parametrize("content", [None, "not valid JSON"])
def test_missing_or_invalid_explicit_surface_does_not_fall_back(tmp_path: Path, content: str | None) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"mcpServers": {"filesystem": {"command": "npx", "args": _server_config().args}}})
    )
    mapping = tmp_path / "surfaces.json"
    mapping.write_text(json.dumps({"filesystem": "surface.json"}))
    if content is not None:
        (tmp_path / "surface.json").write_text(content)
    # Loading fails before resolution; neither pins nor catalog may substitute.
    with pytest.raises((FileNotFoundError, ValueError)):
        load_config(config, mapping, pins_dir=tmp_path)


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


@pytest.mark.parametrize("kind", ["json", "toml"])
@pytest.mark.parametrize("mixed", [False, True])
def test_malformed_entries_are_reported_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str, mixed: bool
) -> None:
    from redteam.chains.__main__ import main
    from redteam.chains.report import build_report

    path = tmp_path / f"config.{kind}"
    if kind == "json":
        entries: dict[str, object] = {"bad": {"command": "server", "args": "secret-value"}}
        if mixed:
            entries["good"] = {"command": "synthetic", "args": []}
        path.write_text(json.dumps({"mcpServers": entries}), encoding="utf-8")
    else:
        content = '[mcp_servers.bad]\ncommand = "server"\nargs = "secret-value"\n'
        if mixed:
            content += '[mcp_servers.good]\ncommand = "synthetic"\nargs = []\n'
        path.write_text(content, encoding="utf-8")
    report = build_report(load_config(path))
    assert report["analysis_incomplete"] is True
    unknown = report["unknown_surfaces"]
    servers = report["servers"]
    assert isinstance(unknown, list) and "bad" in unknown
    assert isinstance(servers, list) and len(servers) == (2 if mixed else 1)
    assert "secret-value" not in repr(report)
    assert main(["run", "--config", str(path)]) == 1
    output = capsys.readouterr().out
    assert "Analysis incomplete" in output and "bad" in output
    assert "secret-value" not in output
    assert main(["run", "--config", str(path), "--allow-incomplete"]) == 0


def test_missing_and_changed_explicit_identity_do_not_match(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    mapping = tmp_path / "mapping.json"
    surface = tmp_path / "surface.json"
    mapping.write_text(json.dumps({"example": "surface.json"}))
    path.write_text(json.dumps({"mcpServers": {"example": {"command": "new", "args": []}}}))
    for identity in (None, {"command": "old", "args": []}):
        data: dict[str, object] = {
            "server_name": "example",
            "source": "fixture",
            "tools": [{"name": "write_file"}],
        }
        if identity is not None:
            data["config"] = identity
        surface.write_text(json.dumps(data))
        assert load_config(path, mapping)[0].tool_surface == "UNKNOWN"


def test_unused_surface_mapping_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": {"example": {"command": "server"}}}))
    (tmp_path / "surface.json").write_text(_surface("write_file").to_json())
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"typo": "surface.json"}))
    with pytest.raises(ValueError, match="unknown server name"):
        load_config(path, mapping)


def test_duplicate_names_across_maps_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"mcpServers": {"same": {"command": "one"}}, "servers": {"same": {"command": "two"}}})
    )
    with pytest.raises(ValueError, match="duplicate server names"):
        load_config(path)
