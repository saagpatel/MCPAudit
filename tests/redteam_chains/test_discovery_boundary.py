"""Discovery regressions on synthetic homes, with optional real shadow-mcp."""

from __future__ import annotations

import builtins
import importlib
import io
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Literal
from unittest.mock import Mock

import pytest

from mcp_audit.models import ClientType, ServerConfig, ToolInfo, TransportType
from mcp_audit.pin_signing import generate_keypair
from mcp_audit.pinning import PinStore
from redteam.chains.__main__ import main
from redteam.chains.discovery import DiscoveryServers, _server, discover_servers
from redteam.chains.dxt import MAX_INPUT_BYTES, DxtCollector, read_regular_file
from redteam.chains.pairs import resolve_configs
from redteam.chains.report import build_report, to_json, to_markdown
from redteam.surface import ServerSurface, SurfaceConfig, SurfaceTool


@dataclass
class _ServerSpec:
    """Exactly the real ServerSpec's fields, including its lack of headers."""

    transport: str = "stdio"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env_keys: list[str] = field(default_factory=list)


@pytest.mark.parametrize("transport", ["http", "sse"])
@pytest.mark.parametrize("binding", ["pin", "explicit", "fallback"])
def test_unavailable_headers_withhold_every_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport: Literal["http", "sse"],
    binding: str,
) -> None:
    try:
        spec_class = importlib.import_module("shadow_mcp.models").ServerSpec
    except ModuleNotFoundError as exc:
        if exc.name not in {"shadow_mcp", "shadow_mcp.models"}:
            raise
        spec_class = _ServerSpec
    spec = spec_class(transport=transport, url="https://example.invalid/mcp")
    assert set(spec_class.model_fields if hasattr(spec_class, "model_fields") else spec.__dict__) == {
        "transport",
        "command",
        "args",
        "url",
        "env_keys",
    }
    discovered = _server(SimpleNamespace(name="remote", spec=spec))
    assert discovered.header_keys_state == "UNAVAILABLE"
    baseline = ServerConfig(
        name="remote",
        client=ClientType.CLAUDE_DESKTOP,
        config_path="synthetic.json",
        transport=TransportType(transport),
        url=spec.url,
        headers_keys=[],  # Explicitly known empty headers on the signed pin.
    )
    pins = tmp_path / "pins"
    keys = generate_keypair(pins / "keys", pins / "trusted-keys.yaml")
    store = PinStore(
        pins / ".mcp-audit-pins.yaml",
        signing_key=keys.private_key_path,
        trusted_keys_path=pins / "trusted-keys.yaml",
    )
    store.pin_server("remote", [ToolInfo(name="historical_tool")], baseline)
    # The same known-empty identity can resolve the signature-verified baseline.
    assert resolve_configs([baseline], pins_dir=pins)[0].source == "pin"
    explicit = ServerSurface(
        server_name="remote",
        source="fixture",
        config=SurfaceConfig(transport=transport, url=spec.url),
        tools=[SurfaceTool(name="explicit_tool")],
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("incomplete launch identity must not attempt any surface binding")

    import redteam.chains.pairs as pairs

    monkeypatch.setattr(pairs, "_pin_surface", forbidden)
    monkeypatch.setattr(pairs, "_explicit_surface_matches", forbidden)
    monkeypatch.setattr(pairs, "manifest_surface", forbidden)
    monkeypatch.setattr(pairs, "catalog_surface", forbidden)
    server = resolve_configs(
        [discovered],
        {"remote": explicit} if binding == "explicit" else None,
        pins_dir=pins if binding == "pin" else None,
    )[0]
    assert server.tool_surface == "UNKNOWN"
    assert server.reason == "launch identity incomplete: header keys unavailable from discovery"
    report = build_report([server])
    assert server.reason in to_json(report) and server.reason in to_markdown(report)
    assert "historical_tool" not in to_json(report)


@pytest.fixture
def real_shadow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = pytest.importorskip("shadow_mcp.config")
    assert isinstance(module, ModuleType)
    pytest.importorskip("shadow_mcp.collectors.base")
    monkeypatch.setenv("SHADOW_MCP_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return module


def _path(paths: object, name: str) -> Path:
    value: object = getattr(paths, name)
    assert isinstance(value, Path)
    return value


@pytest.mark.parametrize("transport", ["http", "sse"])
@pytest.mark.parametrize("headers", [{}, {"X-Profile": "synthetic-profile"}])
def test_real_collector_cannot_match_headerless_pin(
    real_shadow: ModuleType, tmp_path: Path, transport: str, headers: dict[str, str]
) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    desktop = _path(paths, "claude_desktop_config")
    desktop.parent.mkdir(parents=True)
    desktop.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "type": transport,
                        "url": "https://example.invalid/mcp",
                        "headers": headers,
                    }
                }
            }
        )
    )
    pins = tmp_path / "pins"
    keys = generate_keypair(pins / "keys", pins / "trusted-keys.yaml")
    store = PinStore(
        pins / ".mcp-audit-pins.yaml",
        signing_key=keys.private_key_path,
        trusted_keys_path=pins / "trusted-keys.yaml",
    )
    baseline = ServerConfig(
        name="remote",
        client=ClientType.CLAUDE_DESKTOP,
        config_path="synthetic.json",
        transport=TransportType(transport),
        url="https://example.invalid/mcp",
        headers_keys=[],
    )
    store.pin_server("remote", [ToolInfo(name="historical_tool")], baseline)
    servers = discover_servers(pins_dir=pins)
    assert len(servers) == 1
    assert servers[0].tool_surface == "UNKNOWN"
    assert servers[0].reason == "launch identity incomplete: header keys unavailable from discovery"
    assert "historical_tool" not in to_json(build_report(servers))


@pytest.mark.parametrize("failure", ["json", "toml", "unreadable"])
def test_real_collectors_cannot_hide_input_errors(
    real_shadow: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str], failure: str
) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    path = _path(paths, "codex_config" if failure == "toml" else "claude_desktop_config")
    path.parent.mkdir(parents=True)
    path.write_text("[broken = secret-value" if failure == "toml" else '{"private": invalid-secret}')
    if failure == "unreadable":
        path.write_text("{}")
        path.chmod(0)
    try:
        # Confirm the real collector loses the failure before testing the adapter.
        collector_module = importlib.import_module(
            "shadow_mcp.collectors.codex" if failure == "toml" else "shadow_mcp.collectors.claude_desktop"
        )
        collector = (
            collector_module.CodexCollector(paths)
            if failure == "toml"
            else collector_module.ClaudeDesktopCollector(paths)
        )
        assert collector.collect() == []
        servers = discover_servers()
        assert isinstance(servers, DiscoveryServers)
        assert len(servers) == 0
        expected = {"json": "JSONDecodeError", "toml": "TOMLDecodeError", "unreadable": "PermissionError"}
        assert servers.collector_errors == [
            f"{'codex_config' if failure == 'toml' else 'claude_desktop_config'} "
            f"collector error ({expected[failure]})"
        ]
        report = build_report(servers)
        assert report["analysis_incomplete"] is True
        assert "secret-value" not in to_json(report) and "invalid-secret" not in to_json(report)
        assert str(tmp_path) not in repr(servers.collector_errors)
        assert main(["run", "--discover"]) == 1
        assert main(["run", "--discover", "--allow-incomplete"]) == 0
        capsys.readouterr()
    finally:
        path.chmod(0o600)


def test_absent_inputs_are_not_errors(real_shadow: ModuleType) -> None:
    servers = discover_servers()
    assert isinstance(servers, DiscoveryServers)
    assert not servers and servers.collector_errors == []


def test_real_discovery_uses_local_dxt_sightings(real_shadow: ModuleType) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    extension = _path(paths, "claude_extensions_dir") / "synthetic.extension"
    extension.mkdir(parents=True)
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "Synthetic",
                "server": {
                    "mcp_config": {
                        "command": "node",
                        "args": ["${__dirname}/index.js"],
                    }
                },
                "tools": [{"name": "write_file"}],
            }
        )
    )
    servers = discover_servers()
    assert isinstance(servers, DiscoveryServers)
    assert len(servers) == 1 and servers.collector_errors == []
    server = servers[0]
    assert server.source == "dxt-manifest" and server.surface is not None
    assert server.name == "Synthetic" and server.surface.config.args == ["${__dirname}/index.js"]
    assert [tool.name for tool in server.surface.tools] == ["write_file"]
    assert server.provenance_source == "dxt" and server.provenance_location == str(manifest)
    assert servers.source_counts["dxt"] == 1


@pytest.mark.parametrize("unsafe", ["manifest-link", "directory-link", "fifo"])
def test_dxt_discovery_never_opens_unsafe_entries(
    real_shadow: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    root = _path(paths, "claude_extensions_dir")
    root.mkdir(parents=True)
    extension = root / "synthetic.extension"
    private_config = _path(paths, "claude_json")
    private_config.write_text('{"private": "never-read"}')
    if unsafe == "directory-link":
        target = tmp_path / "outside-extension"
        target.mkdir()
        (target / "manifest.json").write_text('{"private": "never-read"}')
        extension.symlink_to(target, target_is_directory=True)
    else:
        extension.mkdir()
        if unsafe == "manifest-link":
            (extension / "manifest.json").symlink_to(private_config)
        else:
            os.mkfifo(extension / "manifest.json")
    opened: list[str] = []
    original_os_open = os.open
    plain_open = Mock(wraps=builtins.open)
    io_open = Mock(wraps=io.open)

    def record_os_open(
        path: str | bytes | os.PathLike[str], flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        opened.append(os.fsdecode(path))
        assert os.fsdecode(path) not in {"manifest.json", str(private_config)}
        if unsafe == "directory-link":
            assert os.fsdecode(path) != extension.name
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    def forbidden_collector(*args: object, **kwargs: object) -> None:
        pytest.fail("raw shadow-mcp DXT collector must never be used")

    monkeypatch.setattr(
        importlib.import_module("shadow_mcp.collectors.dxt"), "DxtCollector", forbidden_collector
    )
    monkeypatch.setattr(os, "open", record_os_open)
    monkeypatch.setattr(builtins, "open", plain_open)
    monkeypatch.setattr(io, "open", io_open)
    servers = discover_servers()
    assert isinstance(servers, DiscoveryServers)
    assert len(servers) == 0
    assert servers.collector_errors == ["DXT manifest skipped (ValueError)"]
    assert build_report(servers)["analysis_incomplete"] is True
    assert "never-read" not in repr(servers.collector_errors)
    assert opened  # The selected config inputs were checked through the reader.
    for call in plain_open.call_args_list + io_open.call_args_list:
        file: object = call.args[0]
        if isinstance(file, (str, Path)):
            assert Path(file).name not in {"manifest.json", private_config.name}


def test_local_dxt_sighting_uses_only_nested_launch(tmp_path: Path) -> None:
    root = tmp_path / "Claude Extensions"
    extension = root / "synthetic.extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "name": "Synthetic",
                "server": {
                    "command": "wrong",
                    "args": ["wrong"],
                    "mcp_config": {
                        "command": "node",
                        "args": ["${__dirname}/index.js"],
                        "env": {"SYNTHETIC_KEY": "never-retained"},
                    },
                },
            }
        )
    )
    collector = DxtCollector(root)
    sightings = collector.collect()
    assert collector.errors == [] and len(sightings) == 1
    assert sightings[0].name == "Synthetic"
    assert sightings[0].spec.command == "node"
    assert sightings[0].spec.args == ["${__dirname}/index.js"]
    assert sightings[0].spec.env_keys == ["SYNTHETIC_KEY"]
    assert "never-retained" not in repr(sightings)


@pytest.mark.parametrize("kind", ["size", "link", "fifo"])
def test_bounded_reader_rejects_unsafe_inputs_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: Literal["size", "link", "fifo"]
) -> None:
    path = tmp_path / "input.json"
    if kind == "size":
        with path.open("wb") as stream:
            stream.truncate(MAX_INPUT_BYTES + 1)
    elif kind == "link":
        target = tmp_path / "other.json"
        target.write_text("{}")
        path.symlink_to(target)
    else:
        os.mkfifo(path)
    original = os.open

    def guarded(
        pathname: str | bytes | os.PathLike[str], flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        assert os.fsdecode(pathname) != path.name
        return original(pathname, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", guarded)
    with pytest.raises(ValueError):
        read_regular_file(path)
