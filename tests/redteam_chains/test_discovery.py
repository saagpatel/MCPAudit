from __future__ import annotations

import json
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
        "    return SimpleNamespace(servers=[server, server], "
        "source_counts={'claude_desktop': 2, 'synthetic-secret-key': 4}, "
        "errors=['synthetic-secret-value at /synthetic/private/path'])\n",
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
        "shadow-mcp source claude_desktop: 2",
        "shadow-mcp source (unrecognized): 4",
        "shadow-mcp collector error (details withheld)",
    ]
    from redteam.chains.report import build_report, to_json

    report = to_json(build_report(servers))
    assert "synthetic-secret-value" not in report
    assert "/synthetic/private/path" not in report
    assert "synthetic-secret-key" not in report


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
    assert (
        capsys.readouterr().err.strip()
        == "set PYTHONPATH=<path-to-shadow-mcp>/src and use uv run --locked ..."
    )


def test_discovery_rejects_foreign_mcp_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit

    monkeypatch.setattr(mcp_audit, "__file__", "/synthetic/site-packages/mcp_audit/__init__.py")
    with pytest.raises(ImportError, match="must be imported from this checkout"):
        discover_servers()


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


def test_discovery_dxt_defaults_and_provenance_override(
    shadow: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redteam.chains.report import build_report, to_json, to_markdown

    discover_servers()  # Load the synthetic adapter modules.
    extensions = tmp_path / "Claude Extensions"
    extension = extensions / "synthetic.filesystem"
    extension.mkdir(parents=True)
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "server": {"command": "node", "args": ["${__dirname}/index.js"]},
                "tools": [{"name": "write_file", "description": "Write a file."}],
            }
        )
    )
    config_module = sys.modules["shadow_mcp.config"]
    monkeypatch.setattr(
        config_module.DiscoveryPaths, "default", lambda: SimpleNamespace(claude_extensions_dir=extensions)
    )
    spec = SimpleNamespace(
        command="node", args=["${__dirname}/index.js"], transport="stdio", url=None, env_keys=[]
    )
    entry = SimpleNamespace(name="Filesystem", spec=spec, provenance=None)
    base_module = sys.modules["shadow_mcp.collectors.base"]

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[entry], source_counts={"dxt": 1}, errors=["synthetic error"])

    monkeypatch.setattr(base_module, "discover_all", discover)
    servers = discover_servers()
    assert servers[0].source == "dxt-manifest"
    report = build_report(servers)
    assert "shadow-mcp source dxt: 1" in to_json(report)
    assert "shadow-mcp collector error" in to_markdown(report)
    entry.provenance = SimpleNamespace(path=manifest)
    # Provenance cannot bypass an explicitly selected, unavailable root.
    assert discover_servers(dxt_dir=tmp_path / "absent")[0].tool_surface == "UNKNOWN"
    assert discover_servers(dxt_dir=extensions)[0].source == "dxt-manifest"


@pytest.mark.parametrize("as_mapping", [False, True])
def test_discovery_dxt_location_selects_exact_manifest_and_settings(
    shadow: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, as_mapping: bool
) -> None:
    discover_servers()  # Load only the synthetic shadow-mcp adapter.
    claude = tmp_path / "Library" / "Application Support" / "Claude"
    extensions = claude / "Claude Extensions"
    settings = claude / "Claude Extensions Settings"
    settings.mkdir(parents=True)
    args = ["${__dirname}/index.js", "${user_config.allowed_directories}"]
    for identifier, tool in (("synthetic.selected", "write_file"), ("synthetic.other", "other_tool")):
        extension = extensions / identifier
        extension.mkdir(parents=True)
        (extension / "manifest.json").write_text(
            json.dumps({"server": {"command": "node", "args": args}, "tools": [{"name": tool}]})
        )
        (settings / f"{identifier}.json").write_text(
            json.dumps({"userConfig": {"allowed_directories": [f"synthetic/{identifier}"]}})
        )
    manifest = extensions / "synthetic.selected" / "manifest.json"
    fields = {"source": "dxt", "location": str(manifest)}
    provenance = fields if as_mapping else SimpleNamespace(**fields)
    spec = SimpleNamespace(
        command="node",
        args=[
            str(extensions / "synthetic.selected" / "index.js"),
            "${user_config.allowed_directories}",
        ],
        transport="stdio",
        url=None,
        env_keys=[],
    )
    entry = SimpleNamespace(name="Filesystem", spec=spec, provenance=provenance)
    duplicate = SimpleNamespace(
        name="Filesystem", spec=spec, provenance=SimpleNamespace(source="desktop", location="synthetic.json")
    )

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[entry, duplicate], source_counts={"dxt": 1}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    # Exact provenance selects one of two manifests with the same placeholder
    # launch identity, within the explicitly selected extensions directory.
    servers = discover_servers(dxt_dir=extensions)
    assert len(servers) == 1
    server = servers[0]
    assert server.source == "dxt-manifest" and server.surface is not None
    assert [tool.name for tool in server.surface.tools] == ["write_file"]
    assert server.roots == ("synthetic/synthetic.selected",)
    assert server.provenance_source == "dxt"
    assert server.provenance_location == str(manifest)


@pytest.mark.parametrize("as_mapping", [False, True])
@pytest.mark.parametrize(
    ("name", "identifier", "args", "tools", "roots"),
    [
        (
            "Filesystem",
            "ant.dir.ant.anthropic.filesystem",
            ["${__dirname}/dist/index.js", "${user_config.allowed_directories}"],
            ["edit_file", "write_file"],
            ["synthetic/project"],
        ),
        (
            "chrome-control",
            "ant.dir.ant.anthropic.chrome-control",
            ["${__dirname}/server/index.js"],
            ["execute_javascript"],
            [],
        ),
    ],
)
def test_discovery_dxt_nested_launch_with_unexpanded_placeholders(
    shadow: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    as_mapping: bool,
    name: str,
    identifier: str,
    args: list[str],
    tools: list[str],
    roots: list[str],
) -> None:
    discover_servers()  # Load only the synthetic shadow-mcp adapter.
    claude = tmp_path / "Library" / "Application Support" / "Claude"
    extensions = claude / "Claude Extensions"
    settings = claude / "Claude Extensions Settings"
    extension = extensions / identifier
    extension.mkdir(parents=True)
    settings.mkdir()
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "server": {
                    "type": "node",
                    "entry_point": args[0].removeprefix("${__dirname}/"),
                    "mcp_config": {"command": "node", "args": args},
                },
                "tools": [{"name": tool} for tool in tools],
            }
        ),
        encoding="utf-8",
    )
    (settings / f"{identifier}.json").write_text(
        json.dumps({"userConfig": {"allowed_directories": roots}}), encoding="utf-8"
    )
    fields = {"source": "dxt", "location": str(manifest)}
    entry = SimpleNamespace(
        name=name,
        spec=SimpleNamespace(command="node", args=args, transport="stdio", url=None, env_keys=[]),
        provenance=fields if as_mapping else SimpleNamespace(**fields),
    )

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[entry], source_counts={"dxt": 1}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    # The collector's direct-child manifest location supplies the root; no home discovery is needed.
    server = discover_servers()[0]
    assert server.tool_surface == "KNOWN" and server.source == "dxt-manifest"
    assert server.surface is not None and server.surface.unverified
    assert [tool.name for tool in server.surface.tools] == tools
    assert server.roots == tuple(roots)
    assert server.provenance_source == "dxt"
    assert server.provenance_location == str(manifest)
