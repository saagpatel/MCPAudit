from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from mcp_audit.models import TransportType
from redteam.chains.__main__ import main
from redteam.chains.discovery import DiscoveryServers, _server, discover_servers


@pytest.fixture
def shadow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    package = tmp_path / "shadow_mcp"
    collectors = package / "collectors"
    collectors.mkdir(parents=True)
    (package / "__init__.py").write_text("constructed = []\ncalls = []\n", encoding="utf-8")
    (collectors / "__init__.py").write_text("", encoding="utf-8")
    (package / "config.py").write_text(
        "class DiscoveryPaths:\n    @classmethod\n    def default(cls):\n        return cls()\n",
        encoding="utf-8",
    )
    (collectors / "base.py").write_text(
        "from types import SimpleNamespace\n"
        "import shadow_mcp\n"
        "def discover_all(paths, *, include_processes, include_cli, collectors):\n"
        "    shadow_mcp.calls.append((paths, include_processes, include_cli, collectors))\n"
        "    spec = SimpleNamespace(transport='stdio', command='npx', args=['server-filesystem', "
        "'synthetic/repo'], url=None, env_keys=['TOKEN'])\n"
        "    server = SimpleNamespace(name='filesystem', spec=spec, provenance=None)\n"
        "    return SimpleNamespace(servers=[server, server], source_counts={'desktop': 2}, "
        "errors=['synthetic error'])\n",
        encoding="utf-8",
    )
    for module, name in (
        ("claude_desktop", "ClaudeDesktopCollector"),
        ("codex", "CodexCollector"),
        ("dxt", "DxtCollector"),
        ("project_mcp", "ProjectMcpJsonCollector"),
        ("claude_code", "ClaudeCodeCollector"),
        ("claude_cli", "ClaudeCliCollector"),
        ("processes", "ProcessCollector"),
    ):
        (collectors / f"{module}.py").write_text(
            f"import shadow_mcp\nclass {name}:\n"
            f"    def __init__(self, paths):\n        shadow_mcp.constructed.append('{name}')\n",
            encoding="utf-8",
        )
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in list(sys.modules):
        if name == "shadow_mcp" or name.startswith("shadow_mcp."):
            monkeypatch.delitem(sys.modules, name)
    yield package
    for name in list(sys.modules):
        if name == "shadow_mcp" or name.startswith("shadow_mcp."):
            sys.modules.pop(name)


def test_discovery_allowlist_mapping_and_notes(shadow: Path) -> None:
    servers = discover_servers()
    module = sys.modules["shadow_mcp"]
    assert module.constructed == [
        "ClaudeDesktopCollector",
        "CodexCollector",
        "DxtCollector",
        "ProjectMcpJsonCollector",
    ]
    paths, processes, cli, collectors = module.calls[0]
    assert paths.__class__.__name__ == "DiscoveryPaths"
    assert processes is False and cli is False and len(collectors) == 4
    assert len(servers) == 1
    assert servers[0].env_keys == ("TOKEN",)
    assert servers[0].source == "unknown"
    assert cast(DiscoveryServers, servers).notes == [
        "shadow-mcp source desktop: 2",
        "shadow-mcp error: synthetic error",
    ]


def test_discovery_claude_code_opt_in(shadow: Path) -> None:
    discover_servers(include_claude_code=True)
    module = sys.modules["shadow_mcp"]
    assert module.constructed[-1] == "ClaudeCodeCollector"
    assert len(module.constructed) == 5
    assert len(module.calls[0][3]) == 5


def test_discovery_maps_nested_spec() -> None:
    spec = SimpleNamespace(
        transport="http",
        command=None,
        args=["synthetic"],
        url="https://example.invalid/mcp",
        env_keys=["Z_KEY", "A_KEY", "Z_KEY"],
    )
    config = _server(SimpleNamespace(name="remote", spec=spec))
    assert config.name == "remote"
    assert config.transport == TransportType.HTTP
    assert config.command is None
    assert config.args == ["synthetic"]
    assert config.url == "https://example.invalid/mcp"
    assert config.env_keys == ["A_KEY", "Z_KEY"]


def test_discovery_missing_package(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "shadow_mcp", None)
    assert main(["run", "--discover"]) == 2
    assert capsys.readouterr().err.strip() == "install shadow-mcp: uv run --with <path-to-shadow-mcp> ..."


def test_discovery_incompatible_package(shadow: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (shadow / "collectors" / "codex.py").write_text("", encoding="utf-8")
    assert main(["run", "--discover"]) == 2
    assert (
        "incompatible shadow-mcp: missing shadow_mcp.collectors.codex.CodexCollector"
        in capsys.readouterr().err
    )
    assert sys.modules["shadow_mcp"].calls == []


def test_discovery_rejects_claude_code_opt_in_with_explicit_config() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["run", "--config", "synthetic.json", "--include-claude-code"])
    assert exc.value.code == 2
