from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import fields, replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import cast

import pytest

from mcp_audit.models import TransportType
from redteam.chains.__main__ import main
from redteam.chains.discovery import DiscoveryServers, _server, discover_servers


@pytest.fixture
def shadow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    package = tmp_path / "shadow_mcp"
    collectors = package / "collectors"
    collectors.mkdir(parents=True)
    (package / "__init__.py").write_text("constructed = []\ncalls = []\n", encoding="utf-8")
    (collectors / "__init__.py").write_text("", encoding="utf-8")
    (package / "config.py").write_text(
        "from dataclasses import dataclass\n"
        "from pathlib import Path\n"
        "@dataclass(frozen=True)\n"
        "class DiscoveryPaths:\n"
        "    home: Path\n"
        "    claude_json: Path\n"
        "    claude_desktop_config: Path\n"
        "    claude_extensions_dir: Path\n"
        "    codex_config: Path\n"
        "    codex_profile_configs: list[Path]\n"
        "    projects_root: Path | None\n"
        "    project_glob_depth: int\n"
        "    def __getattr__(self, name):\n"
        "        raise AssertionError(f'unexpected DiscoveryPaths field: {name}')\n"
        "    @classmethod\n"
        "    def default(cls):\n"
        "        root = Path.home() / 'synthetic-home'\n"
        "        return cls(root, root / 'code.json', root / 'desktop.json',\n"
        "                   root / 'Claude Extensions', root / 'config.toml',\n"
        "                   [root / 'profiles' / 'synthetic.toml',\n"
        "                    root / 'profiles' / 'synthetic' / 'config.toml'],\n"
        "                   root / 'projects', 4)\n",
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


def test_discovery_paths_field_contract(shadow: Path) -> None:
    discover_servers(include_claude_code=True, dxt_dir=shadow / "selected")
    paths_class = sys.modules["shadow_mcp.config"].DiscoveryPaths
    assert [field.name for field in fields(paths_class)] == [
        "home",
        "claude_json",
        "claude_desktop_config",
        "claude_extensions_dir",
        "codex_config",
        "codex_profile_configs",
        "projects_root",
        "project_glob_depth",
    ]


def test_discovery_allowlist_mapping_and_notes(shadow: Path) -> None:
    servers = discover_servers()
    module = sys.modules["shadow_mcp"]
    assert module.constructed == [
        "ClaudeDesktopCollector",
        "CodexCollector",
        "ProjectMcpJsonCollector",
    ]
    paths, processes, cli, collectors = module.calls[0]
    assert paths.__class__.__name__ == "DiscoveryPaths"
    assert processes is False and cli is False and len(collectors) == 4
    from redteam.chains.dxt import DxtCollector

    assert isinstance(collectors[2], DxtCollector)
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
    document = build_report(servers)
    assert document["analysis_incomplete"] is True
    assert document["source_counts"] == {"claude_desktop": 2, "unrecognized": 4}
    assert document["collector_errors"] == ["shadow-mcp collector error (details withheld)"]


def test_discovery_claude_code_opt_in(shadow: Path) -> None:
    discover_servers(include_claude_code=True)
    module = sys.modules["shadow_mcp"]
    assert module.constructed[-1] == "ClaudeCodeCollector"
    assert len(module.constructed) == 4
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


def test_cli_checks_package_origin_before_loading_core_apis(tmp_path: Path) -> None:
    package = tmp_path / "mcp_audit"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "models.py").write_text("raise AssertionError('foreign core API must not be imported')")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "redteam.chains", "run", "--config", "synthetic.json"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(tmp_path), str(root)))},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stderr.strip() == "mcp_audit must be imported from this checkout's src/ directory"


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
                "server": {"mcp_config": {"command": "node", "args": ["${__dirname}/index.js"]}},
                "tools": [{"name": "write_file", "description": "Write a file."}],
            }
        )
    )
    config_module = sys.modules["shadow_mcp.config"]
    paths = config_module.DiscoveryPaths.default()
    monkeypatch.setattr(
        config_module.DiscoveryPaths,
        "default",
        lambda: replace(
            paths,
            claude_extensions_dir=extensions,
        ),
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
    entry.provenance = SimpleNamespace(source="dxt", location=str(manifest))
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
            json.dumps(
                {"server": {"mcp_config": {"command": "node", "args": args}}, "tools": [{"name": tool}]}
            )
        )
        (settings / f"{identifier}.json").write_text(
            json.dumps({"userConfig": {"allowed_directories": [f"synthetic/{identifier}"]}})
        )
    manifest = extensions / "synthetic.selected" / "manifest.json"
    fields = {"source": "dxt", "location": str(manifest)}
    provenance = fields if as_mapping else SimpleNamespace(**fields)
    spec = SimpleNamespace(
        command="node",
        args=args,
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
    paths_class = sys.modules["shadow_mcp.config"].DiscoveryPaths
    paths = paths_class.default()
    monkeypatch.setattr(
        paths_class,
        "default",
        lambda: replace(
            paths,
            claude_extensions_dir=extensions,
        ),
    )
    # Exact collector provenance selects the manifest within the default root.
    server = discover_servers()[0]
    assert server.tool_surface == "KNOWN" and server.source == "dxt-manifest"
    assert server.surface is not None and server.surface.unverified
    assert [tool.name for tool in server.surface.tools] == tools
    assert server.roots == tuple(roots)
    assert server.provenance_source == "dxt"
    assert server.provenance_location == str(manifest)


def test_collector_errors_fail_cli_unless_explicitly_allowed(
    shadow: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.json"
    assert main(["run", "--discover", "--json", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["analysis_incomplete"] is True
    assert report["collector_errors"]
    assert "Collector errors:" in capsys.readouterr().out
    assert main(["run", "--discover", "--allow-incomplete"]) == 0


def test_collector_errors_are_incomplete_even_without_servers(
    shadow: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redteam.chains.report import build_report

    discover_servers()

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[], source_counts={}, errors=["private collector error"])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    report = build_report(discover_servers())
    assert report["analysis_incomplete"] is True
    assert "private collector error" not in repr(report)
    inputs: list[Path] = []
    discover_servers(input_paths=inputs)
    assert any(path.name == "npm-playwright-mcp-0.0.76.json" for path in inputs)


@pytest.mark.parametrize("path_field", ["location", "config_path", "source_path"])
def test_discovered_config_and_hardlink_cannot_be_overwritten(
    shadow: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path_field: str
) -> None:
    discover_servers()
    config = tmp_path / "synthetic.json"
    config.write_text("preserved config")
    alias = tmp_path / "alias.json"
    alias.hardlink_to(config)
    entry = SimpleNamespace(
        name="synthetic",
        spec=SimpleNamespace(transport="stdio", command="inert", args=[], url=None, env_keys=[]),
        provenance=SimpleNamespace(source="codex", **{path_field: str(config)}),
    )

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[entry], source_counts={"codex": 1}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    for output in (config, alias):
        assert main(["run", "--discover", "--json", str(output)]) == 2
        assert config.read_text() == "preserved config"


def test_dxt_default_directory_is_protected_from_report_writes(
    shadow: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    discover_servers()
    root = tmp_path / "Claude Extensions"
    root.mkdir()
    paths_class = sys.modules["shadow_mcp.config"].DiscoveryPaths
    paths = paths_class.default()
    monkeypatch.setattr(
        paths_class,
        "default",
        lambda: replace(paths, claude_extensions_dir=root),
    )
    output = root / "synthetic.extension" / "manifest.json"
    assert main(["run", "--discover", "--json", str(output)]) == 2
    assert not output.exists()


def _fixture_path(paths: object, field: str) -> Path:
    value: object = getattr(paths, field)
    assert isinstance(value, Path)
    return value


def test_project_protection_matches_collector_bounds(tmp_path: Path) -> None:
    from redteam.chains.discovery import _project_files

    for name in (
        ".mcp.json",
        "project/mcp.json",
        ".cursor/.mcp.json",
        ".vscode/mcp.json",
        "node_modules/.mcp.json",
        ".hidden/.mcp.json",
        "project/deep/.mcp.json",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    assert set(_project_files(tmp_path, 2)) == {
        tmp_path / ".mcp.json",
        tmp_path / "project/mcp.json",
        tmp_path / ".cursor/.mcp.json",
        tmp_path / ".vscode/mcp.json",
    }


@pytest.fixture
def empty_shadow(shadow: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[object, SimpleNamespace, ModuleType]:
    module = importlib.import_module("shadow_mcp")
    paths: object = importlib.import_module("shadow_mcp.config").DiscoveryPaths.default()
    result = SimpleNamespace(servers=[], source_counts={}, errors=[])

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        module.calls.append((paths, include_processes, include_cli, collectors))
        return result

    monkeypatch.setattr(importlib.import_module("shadow_mcp.collectors.base"), "discover_all", discover)
    return paths, result, module


@pytest.mark.parametrize("error_only", [False, True])
@pytest.mark.parametrize("output_flag", ["--json", "--md"])
@pytest.mark.parametrize("alias_kind", ["direct", "symlink", "hardlink"])
@pytest.mark.parametrize(
    "source",
    ["desktop", "codex", "profile-flat", "profile-directory", "project-root", "project-nested", "code"],
)
def test_empty_or_failed_config_is_protected_before_collection(
    empty_shadow: tuple[object, SimpleNamespace, ModuleType],
    tmp_path: Path,
    source: str,
    alias_kind: str,
    output_flag: str,
    error_only: bool,
) -> None:
    paths, result, module = empty_shadow
    sources = {
        "desktop": _fixture_path(paths, "claude_desktop_config"),
        "codex": _fixture_path(paths, "codex_config"),
        "profile-flat": _fixture_path(paths, "home") / "profiles" / "synthetic.toml",
        "profile-directory": _fixture_path(paths, "home") / "profiles" / "synthetic" / "config.toml",
        "project-root": _fixture_path(paths, "projects_root") / ".mcp.json",
        "project-nested": _fixture_path(paths, "projects_root") / "group" / "project" / ".mcp.json",
        "code": _fixture_path(paths, "claude_json"),
    }
    config = sources[source]
    original = b"invalid synthetic config" if error_only else b"{}"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_bytes(original)
    result.errors = ["synthetic collector error"] if error_only else []
    output = config
    if alias_kind != "direct":
        output = tmp_path / "alias.json"
        if alias_kind == "symlink":
            output.symlink_to(config)
        else:
            output.hardlink_to(config)
    args = ["run", "--discover", output_flag, str(output)]
    if source == "code":
        args.append("--include-claude-code")
    assert main(args) == 2
    assert module.constructed == [] and module.calls == []
    assert config.read_bytes() == original and output.read_bytes() == original


def test_claude_code_path_is_registered_only_when_opted_in(
    empty_shadow: tuple[object, SimpleNamespace, ModuleType],
) -> None:
    paths, _, module = empty_shadow
    inputs: list[Path] = []
    discover_servers(input_paths=inputs)
    assert _fixture_path(paths, "claude_json") not in inputs
    assert "ClaudeCodeCollector" not in module.constructed
    discover_servers(input_paths=inputs, include_claude_code=True)
    assert _fixture_path(paths, "claude_json") in inputs


@pytest.mark.parametrize("override", [False, True])
@pytest.mark.parametrize("settings", [False, True])
@pytest.mark.parametrize("output_flag", ["--json", "--md"])
def test_reports_cannot_be_created_in_empty_metadata_directories(
    empty_shadow: tuple[object, SimpleNamespace, ModuleType],
    tmp_path: Path,
    override: bool,
    settings: bool,
    output_flag: str,
) -> None:
    paths, _, module = empty_shadow
    extensions = (
        tmp_path / "selected" / "Claude Extensions"
        if override
        else _fixture_path(paths, "claude_extensions_dir")
    )
    root = extensions.parent / "Claude Extensions Settings" if settings else extensions
    root.mkdir(parents=True)
    alias = tmp_path / "directory-alias"
    alias.symlink_to(root, target_is_directory=True)
    output = alias / "new-report.json"
    args = ["run", "--discover", output_flag, str(output)]
    if override:
        args.extend(["--dxt-dir", str(extensions)])
    assert main(args) == 2
    assert module.constructed == [] and module.calls == []
    assert not output.exists()


@pytest.mark.parametrize("directory", ["claude_extensions_dir", "claude_extensions_settings_dir"])
@pytest.mark.parametrize("output_flag", ["--json", "--md"])
@pytest.mark.parametrize("alias_kind", ["direct", "symlink", "hardlink"])
def test_empty_extension_metadata_is_protected_before_collection(
    empty_shadow: tuple[object, SimpleNamespace, ModuleType],
    tmp_path: Path,
    directory: str,
    output_flag: str,
    alias_kind: str,
) -> None:
    paths, result, module = empty_shadow
    extensions = _fixture_path(paths, "claude_extensions_dir")
    root = (
        extensions.parent / "Claude Extensions Settings" if directory.endswith("settings_dir") else extensions
    )
    metadata = root / ("empty.json" if directory.endswith("settings_dir") else "empty/manifest.json")
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_bytes(b"{}")
    result.errors = ["synthetic metadata error"]
    output = metadata
    if alias_kind != "direct":
        output = tmp_path / "metadata-alias.json"
        if alias_kind == "symlink":
            output.symlink_to(metadata)
        else:
            output.hardlink_to(metadata)
    assert main(["run", "--discover", output_flag, str(output)]) == 2
    assert module.constructed == [] and module.calls == []
    assert metadata.read_bytes() == output.read_bytes() == b"{}"


def test_dxt_override_is_applied_to_collectors_before_discovery(
    empty_shadow: tuple[object, SimpleNamespace, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, result, module = empty_shadow
    override = tmp_path / "selected" / "Claude Extensions"
    extension = override / "synthetic.extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "server": {"mcp_config": {"command": "node", "args": ["${__dirname}/index.js"]}},
                "tools": [{"name": "selected_tool"}],
            }
        )
    )
    spec = SimpleNamespace(
        transport="stdio", command="node", args=["${__dirname}/index.js"], url=None, env_keys=[]
    )
    result.servers = [
        SimpleNamespace(
            name="selected", spec=spec, provenance={"source": "dxt", "location": extension / "manifest.json"}
        )
    ]
    dxt_module = importlib.import_module("shadow_mcp.collectors.dxt")

    class DxtCollector:
        def __init__(self, selected: object) -> None:
            pytest.fail("shadow-mcp's DxtCollector must never be instantiated")

    monkeypatch.setattr(dxt_module, "DxtCollector", DxtCollector)
    original_glob = Path.glob

    def guarded_glob(path: Path, pattern: str, **kwargs: object) -> Iterator[Path]:
        assert path != _fixture_path(paths, "claude_extensions_dir")
        assert path != _fixture_path(paths, "claude_extensions_dir").parent / "Claude Extensions Settings"
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    servers = discover_servers(dxt_dir=override)
    collected_paths = module.calls[0][0]
    assert _fixture_path(collected_paths, "claude_extensions_dir") == override
    assert _fixture_path(paths, "claude_extensions_dir") != override  # Defaults were not mutated.
    assert len(servers) == 1 and servers[0].source == "dxt-manifest"
    assert servers[0].surface is not None
    assert [tool.name for tool in servers[0].surface.tools] == ["selected_tool"]


@pytest.mark.parametrize(
    "field,value", [("transport", "http"), ("env_keys", ["OTHER"]), ("headers_keys", ["TOKEN"])]
)
def test_conflicting_duplicate_metadata_fails_closed(
    shadow: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    discover_servers()
    first = SimpleNamespace(transport="stdio", command="inert", args=[], url=None, env_keys=[])
    second = SimpleNamespace(**vars(first))
    setattr(second, field, value)
    entries = [SimpleNamespace(name="same", spec=spec, provenance=None) for spec in (first, second)]

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=entries, source_counts={"codex": 2}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    with pytest.raises(ValueError, match="conflicting metadata"):
        discover_servers()


def test_discovered_duplicate_names_never_collide_with_configured_names(
    shadow: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    discover_servers()
    entries = [
        SimpleNamespace(
            name=name,
            spec=SimpleNamespace(transport="stdio", command=command, args=[], url=None, env_keys=[]),
            provenance=None,
        )
        for name, command in (("same", "first"), ("same", "second"), ("same [discovered entry 1]", "third"))
    ]

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=entries, source_counts={"codex": 3}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    servers = discover_servers()
    assert len({server.name for server in servers}) == 3


@pytest.mark.parametrize("location", [None, "manifest.json", "synthetic/other.json"])
def test_invalid_dxt_location_cannot_fall_back_to_another_manifest(
    shadow: Path, monkeypatch: pytest.MonkeyPatch, location: str | None
) -> None:
    discover_servers()
    entry = SimpleNamespace(
        name="Filesystem",
        spec=SimpleNamespace(
            transport="stdio", command="node", args=["${__dirname}/index.js"], url=None, env_keys=[]
        ),
        provenance=SimpleNamespace(source="dxt", location=location),
    )

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=[entry], source_counts={"dxt": 1}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    with pytest.raises(ValueError, match="DXT provenance"):
        discover_servers()


@pytest.mark.parametrize("damage", ["mismatched", "missing-entry"])
def test_display_disambiguation_cannot_bypass_same_name_pin_gate(
    shadow: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from mcp_audit.models import ToolInfo
    from mcp_audit.pin_signing import generate_keypair
    from mcp_audit.pinning import PinStore

    discover_servers()
    pins = tmp_path / "pins"
    trusted_keys = pins / "trusted-keys.yaml"
    key = generate_keypair(pins / "keys", trusted_keys)
    store = PinStore(
        pins / ".mcp-audit-pins.yaml", signing_key=key.private_key_path, trusted_keys_path=trusted_keys
    )
    spec = SimpleNamespace(
        transport="stdio", command="npx", args=["@playwright/mcp@0.0.76"], url=None, env_keys=[]
    )
    config = _server(SimpleNamespace(name="browser", spec=spec))
    stale = config.model_copy(update={"args": ["@playwright/mcp@0.0.75"]})
    if damage == "missing-entry":
        store.pin_server("other", [ToolInfo(name="old_tool")], stale)
        before = store.path.read_bytes()
    store.pin_server(config.name, [ToolInfo(name="old_tool")], stale)
    if damage == "missing-entry":
        store.path.write_bytes(before)
    other_spec = SimpleNamespace(**vars(spec))
    other_spec.args = ["-y", "@playwright/mcp@0.0.76"]
    entries = [SimpleNamespace(name="browser", spec=item, provenance=None) for item in (spec, other_spec)]

    def discover(paths: object, *, include_processes: bool, include_cli: bool, collectors: object) -> object:
        return SimpleNamespace(servers=entries, source_counts={"codex": 2}, errors=[])

    monkeypatch.setattr(sys.modules["shadow_mcp.collectors.base"], "discover_all", discover)
    servers = discover_servers(pins_dir=pins)
    assert len({server.name for server in servers}) == 2
    assert all(server.tool_surface == "UNKNOWN" for server in servers)
    assert all("withheld" in (server.reason or "") for server in servers)
