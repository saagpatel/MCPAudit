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
from redteam.chains.discovery import (
    DiscoveryServers,
    _dropped_entries,
    _server,
    _validate_config_files,
    discover_servers,
)
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


@pytest.fixture(
    params=["map", "entry", "args", "args-item", "command", "url", "env", "headers", "launch", "mix"]
)
def malformed_launch(request: pytest.FixtureRequest) -> tuple[str, str, str]:
    """Equivalent malformed JSON/TOML documents, containing sentinel values."""
    cases: dict[str, tuple[object, str, str]] = {
        "map": ([], 'mcp_servers = ["never-retained"]', "mcpServers"),
        "entry": ({"broken": []}, 'mcp_servers.broken = ["never-retained"]', "mcpServers"),
        "args": (
            {"command": "node", "args": "never-retained"},
            'command = "node"\nargs = "never-retained"',
            "args",
        ),
        "args-item": ({"command": "node", "args": [1]}, 'command = "node"\nargs = [1]', "args"),
        "command": ({"command": ["never-retained"]}, 'command = ["never-retained"]', "command"),
        "url": ({"url": ["never-retained"]}, 'url = ["never-retained"]', "url"),
        "env": (
            {"command": "node", "env": ["never-retained"]},
            'command = "node"\nenv = ["never-retained"]',
            "env",
        ),
        "headers": (
            {"url": "https://example.invalid", "headers": ["never-retained"]},
            'url = "https://example.invalid"\nheaders = ["never-retained"]',
            "headers",
        ),
        "launch": ({"env": {"TOKEN": "never-retained"}}, 'env = {TOKEN = "never-retained"}', "command/url"),
        "mix": (
            {"broken": [], "valid": {"command": "node"}},
            'mcp_servers.broken = []\n[mcp_servers.valid]\ncommand = "node"',
            "mcpServers",
        ),
    }
    case = str(request.param)
    raw, toml, field = cases[case]
    block = raw if case in {"map", "entry", "mix"} else {"broken": raw}
    if case not in {"map", "entry", "mix"}:
        toml = "[mcp_servers.broken]\n" + toml
    return json.dumps({"mcpServers": block}), toml, field


@pytest.mark.parametrize(
    "kind", ["claude_desktop_config", "project_config", "codex_config", "codex_profile_config"]
)
def test_config_shape_validation_is_value_free(
    tmp_path: Path, kind: str, malformed_launch: tuple[str, str, str]
) -> None:
    json_content, toml_content, field = malformed_launch
    codex = kind.startswith("codex")
    path = tmp_path / ("config.toml" if codex else "mcp.json")
    path.write_text(toml_content if codex else json_content)
    errors, blocked, _ = _validate_config_files([(kind, path)])
    assert errors and blocked
    expected_field = "mcp_servers" if codex and field == "mcpServers" else field
    assert any(f"field {expected_field} (" in error for error in errors)
    assert all(error.startswith(f"{kind} collector error:") for error in errors)
    if field != "mcpServers" or '"broken"' in json_content:
        assert any('entry "broken"' in error for error in errors)
    assert "never-retained" not in repr(errors) and str(tmp_path) not in repr(errors)


@pytest.mark.parametrize(
    "kind", ["claude_desktop_config", "codex_config", "codex_profile_config", "project_config"]
)
def test_real_collectors_cannot_hide_malformed_launches(
    real_shadow: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    malformed_launch: tuple[str, str, str],
) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    if kind == "codex_profile_config":
        path = _path(paths, "codex_config").parent / "synthetic.config.toml"
    elif kind == "project_config":
        path = _path(paths, "projects_root") / "synthetic" / ".mcp.json"
    else:
        path = _path(paths, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(malformed_launch[1] if kind.startswith("codex") else malformed_launch[0])
    servers = discover_servers()
    assert isinstance(servers, DiscoveryServers)
    assert servers.collector_errors and not servers
    report = build_report(servers)
    assert report["analysis_incomplete"] is True
    assert "never-retained" not in to_json(report)
    assert str(tmp_path) not in repr(servers.collector_errors)
    assert main(["run", "--discover"]) == 1
    capsys.readouterr()


@pytest.mark.parametrize("kind", ["claude_desktop_config", "codex_config", "project_config"])
def test_real_collector_dropped_sightings_mark_incomplete(
    real_shadow: ModuleType, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    paths: object = real_shadow.DiscoveryPaths.default()
    if kind == "project_config":
        path = _path(paths, "projects_root") / "synthetic" / ".mcp.json"
        module, name = "project_mcp", "ProjectMcpJsonCollector"
    else:
        path = _path(paths, kind)
        module, name = (
            ("codex", "CodexCollector")
            if kind == "codex_config"
            else ("claude_desktop", "ClaudeDesktopCollector")
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '[mcp_servers.valid]\ncommand = "node"'
        if kind == "codex_config"
        else '{"mcpServers": {"valid": {"command": "node"}}}'
    )
    initial = discover_servers()
    assert isinstance(initial, DiscoveryServers) and not initial.collector_errors
    collector_class = getattr(importlib.import_module(f"shadow_mcp.collectors.{module}"), name)
    monkeypatch.setattr(collector_class, "collect", lambda self: [])
    servers = discover_servers()
    assert isinstance(servers, DiscoveryServers)
    assert servers.collector_errors == [f"{kind} collector dropped 1 entries"]
    assert build_report(servers)["analysis_incomplete"] is True


def test_sighting_counts_are_per_file_and_before_deduplication(tmp_path: Path) -> None:
    first, second = tmp_path / "first.toml", tmp_path / "second.toml"
    entries: list[object] = [
        SimpleNamespace(provenance={"source": "codex", "location": str(first)}) for _ in range(2)
    ]
    assert _dropped_entries(
        entries, {("codex_config", first): 2, ("codex_profile_config", second): 1}, set()
    ) == ["codex_profile_config collector dropped 1 entries"]


@pytest.mark.parametrize("kind", ["claude_desktop_config", "codex_config"])
def test_valid_launch_shapes_and_missing_server_maps_are_allowed(tmp_path: Path, kind: str) -> None:
    codex = kind == "codex_config"
    path = tmp_path / ("config.toml" if codex else "mcp.json")
    path.write_text(
        '[mcp_servers.valid]\ncommand = "node"\nargs = ["synthetic.js"]\n'
        "env = {TOKEN = 42}\nheaders = {X = 42}"
        if codex
        else json.dumps(
            {
                "mcpServers": {
                    "valid": {
                        "command": "node",
                        "args": ["synthetic.js"],
                        "env": {"TOKEN": 42},
                        "headers": {"X": 42},
                    }
                }
            }
        )
    )
    assert _validate_config_files([(kind, path)]) == ([], set(), {(kind, path): 1})
    path.write_text("" if codex else "{}")
    assert _validate_config_files([(kind, path)]) == ([], set(), {(kind, path): 0})


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
