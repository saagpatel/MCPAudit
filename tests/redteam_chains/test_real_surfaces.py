"""Offline manifest/catalog regressions; all workstation inputs are synthetic."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_audit.models import ClientType, ServerConfig, TransportType
from redteam.catalog import catalog_surface, load_catalog
from redteam.chains.__main__ import main
from redteam.chains.discovery import DiscoveryServers
from redteam.chains.dxt import _document_at, extension_directory, manifest_surface
from redteam.chains.labeler import label_server
from redteam.chains.pairs import ConfiguredServer, resolve_configs
from redteam.chains.report import build_report, to_json, to_markdown
from redteam.chains.reproduce import ReproductionResult
from redteam.surface import ServerSurface, SurfaceConfig, SurfaceTool


def _config(name: str = "Filesystem", command: str = "node", args: list[str] | None = None) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_DESKTOP,
        config_path="synthetic.json",
        command=command,
        args=args
        if args is not None
        else ["${__dirname}/dist/index.js", "${user_config.allowed_directories}"],
    )


def _extension(tmp_path: Path, name: str = "synthetic.filesystem") -> tuple[Path, Path]:
    extensions = tmp_path / "Claude Extensions"
    extension = extensions / name
    extension.mkdir(parents=True)
    config = _config()
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "server": {"mcp_config": {"command": config.command, "args": config.args}},
                "tools": [{"name": "write_file", "description": "Write a file."}, {"name": "edit_file"}],
            }
        )
    )
    return extensions, extension


def test_selected_extension_cannot_bypass_a_missing_requested_root(tmp_path: Path) -> None:
    _, extension = _extension(tmp_path)
    surface, _, reason = manifest_surface(_config(), tmp_path / "missing-root", extension)
    assert surface is None and reason is not None


def test_selected_extension_link_cannot_alias_another_identity(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    alias = extensions / "alias"
    alias.symlink_to(extension, target_is_directory=True)
    surface, _, reason = manifest_surface(_config(), extensions, alias)
    assert surface is None and reason is not None


def test_metadata_reader_rejects_parent_links_and_nonprivate_files(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    alias = tmp_path / "linked-parent"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        _document_at(alias / extensions.name, extension.name, "manifest.json")
    manifest = extension / "manifest.json"
    manifest.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text('{"synthetic": true}')
    os.link(outside, manifest)
    with pytest.raises(ValueError, match="regular file"):
        _document_at(extensions, extension.name, "manifest.json")
    manifest.unlink()
    os.mkfifo(manifest)
    with pytest.raises(ValueError, match="regular file"):
        _document_at(extensions, extension.name, "manifest.json")


def test_manifest_tools_roots_and_only_allowlisted_metadata_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extensions, extension = _extension(tmp_path)
    settings = tmp_path / "Claude Extensions Settings"
    settings.mkdir()
    home = tmp_path / "synthetic-home"
    (settings / f"{extension.name}.json").write_text(
        json.dumps(
            {
                "userConfig": {
                    "allowed_directories": [str(home / "project"), str(home / "project")],
                    "unrelated_secret": "never-retained",
                }
            }
        )
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    original = Path.read_text
    reads: list[Path] = []
    from redteam.chains import dxt

    original_document_at = dxt._document_at
    metadata_reads: list[Path] = []

    def guarded_document_at(root: Path, directory: str, filename: str) -> dict[str, object]:
        path = root / directory / filename
        metadata_reads.append(path)
        assert path == extension / "manifest.json" or path == settings / f"{extension.name}.json"
        return original_document_at(root, directory, filename)

    monkeypatch.setattr(dxt, "_document_at", guarded_document_at)

    def guarded(path: Path, *args: object, **kwargs: object) -> str:
        reads.append(path)
        assert (
            path.name == "manifest.json"
            or path == settings / f"{extension.name}.json"
            or path.parent.name == "catalog"
        )
        return original(path, encoding="utf-8")

    monkeypatch.setattr(Path, "read_text", guarded)
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.source == "dxt-manifest"
    assert server.roots == (str(home / "project"),)
    assert server.surface is not None and server.surface.unverified
    assert all(not tool.input_schema for tool in server.surface.tools)
    assert {label.tool for label in label_server(server.surface) if label.tag == "writes_file"} == {
        "write_file",
        "edit_file",
    }
    report = build_report([server])
    assert "~/project" in to_json(report) and "~/project" in to_markdown(report)
    assert "never-retained" not in repr(server) + to_json(report)
    assert extension / "manifest.json" in metadata_reads
    assert settings / f"{extension.name}.json" in metadata_reads


def test_manifest_missing_settings_is_unknown_roots(tmp_path: Path) -> None:
    extensions, _ = _extension(tmp_path)
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is not None and server.roots == ()
    assert "unknown" in to_markdown(build_report([server]))


def test_discovery_does_not_fall_back_to_shadow_default() -> None:
    server = resolve_configs([_config()])[0]
    assert server.surface is None
    assert server.reason is not None


def test_invalid_settings_preserves_manifest_tools(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    settings = tmp_path / "Claude Extensions Settings"
    settings.mkdir()
    (settings / f"{extension.name}.json").write_text('{"private": BROKEN')
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is not None and server.roots == ()
    assert server.reason is not None and "roots unknown" in server.reason


def test_settings_symlink_to_another_extension_is_rejected(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    settings = tmp_path / "Claude Extensions Settings"
    settings.mkdir()
    actual = settings / "other-extension.json"
    actual.write_text(
        json.dumps({"userConfig": {"allowed_directories": ["synthetic/wrong-root"]}}),
        encoding="utf-8",
    )
    (settings / f"{extension.name}.json").symlink_to(actual)
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is not None and server.roots == ()
    assert server.reason is not None and "roots unknown" in server.reason
    assert "private" not in server.reason


def test_manifest_ambiguous_and_malformed_fail_closed(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    _extension(tmp_path, "second")
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is None and server.reason is not None and "ambiguous" in server.reason
    # Explicit collector provenance disambiguates identical placeholder launches.
    selected = resolve_configs([_config()], dxt_dir=extensions, extensions={"Filesystem": extension})[0]
    assert selected.source == "dxt-manifest"
    (extension / "manifest.json").write_text('{"tools": "private-content" BROKEN')
    failed = resolve_configs([_config()], extensions={"Filesystem": extension})[0]
    assert failed.surface is None and "private-content" not in str(failed.reason)


def test_explicit_metadata_precedes_dxt_without_manifest_read(tmp_path: Path) -> None:
    surface = ServerSurface(
        server_name="Filesystem",
        source="fixture",
        config=SurfaceConfig(command="node", args=_config().args),
        tools=[SurfaceTool(name="explicit")],
    )
    server = resolve_configs(
        [_config()], {"Filesystem": surface}, extensions={"Filesystem": tmp_path / "absent"}
    )[0]
    assert server.source == "explicit" and server.surface is not None
    assert server.surface.tools[0].name == "explicit"


def test_manifest_symlink_escape_is_unknown(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    outside = tmp_path / "other.json"
    (extension / "manifest.json").rename(outside)
    (extension / "manifest.json").symlink_to(outside)
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is None and "invalid" in str(server.reason)


def test_provenance_extension_must_stay_inside_selected_extensions_root(tmp_path: Path) -> None:
    extensions, _ = _extension(tmp_path)
    outside = tmp_path / "outside"
    _, extension = _extension(outside)
    server = resolve_configs([_config()], dxt_dir=extensions, extensions={"Filesystem": extension})[0]
    assert server.surface is None and "invalid" in str(server.reason)


def test_explicit_extension_outside_named_root_fails_closed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "manifest.json").write_text(
        json.dumps(
            {"server": {"command": "node", "args": _config().args}, "tools": [{"name": "write_file"}]}
        ),
        encoding="utf-8",
    )
    server = resolve_configs([_config()], extensions={"Filesystem": outside})[0]
    assert server.surface is None and server.reason is not None


def test_provenance_selected_manifest_args_must_match_launch(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "server": {"command": "node", "args": ["${__dirname}/different.js", _config().args[1]]},
                "tools": [{"name": "write_file"}],
            }
        ),
        encoding="utf-8",
    )
    config = _config(args=[str(extension / "index.js"), "${user_config.allowed_directories}"])
    server = resolve_configs([config], dxt_dir=extensions, extensions={"Filesystem": extension})[0]
    assert server.surface is None and "unmatched" in str(server.reason)


def test_settings_directory_symlink_escape_is_reported(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    outside = tmp_path / "outside-settings"
    outside.mkdir()
    (outside / f"{extension.name}.json").write_text(
        json.dumps({"userConfig": {"allowed_directories": ["synthetic/wrong-root"]}}),
        encoding="utf-8",
    )
    (tmp_path / "Claude Extensions Settings").symlink_to(outside, target_is_directory=True)
    server = resolve_configs([_config()], dxt_dir=extensions)[0]
    assert server.surface is not None and server.roots == ()
    assert server.reason is not None and "roots unknown" in server.reason


def test_provenance_manifest_command_must_match_selected_server(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "server": {"command": "different-launcher", "args": _config().args},
                "tools": [{"name": "write_file"}],
            }
        ),
        encoding="utf-8",
    )
    server = resolve_configs([_config()], dxt_dir=extensions, extensions={"Filesystem": extension})[0]
    assert server.surface is None and "unmatched" in str(server.reason)


@pytest.mark.parametrize(
    "launch",
    [
        None,
        {"command": "different-launcher", "args": _config().args},
        {"command": "node", "args": ["${__dirname}/different.js"]},
    ],
)
def test_nested_dxt_launch_cannot_fall_back_to_matching_outer_fields(tmp_path: Path, launch: object) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "server": {"command": "node", "args": _config().args, "mcp_config": launch},
                "tools": [{"name": "write_file"}],
            }
        ),
        encoding="utf-8",
    )
    server = resolve_configs([_config()], dxt_dir=extensions, extensions={"Filesystem": extension})[0]
    assert server.tool_surface == "UNKNOWN" and server.surface is None
    assert server.reason is not None and "unmatched" in server.reason


def test_provenance_requires_dxt_manifest_in_extensions_layout(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    assert extension_directory({"source": "dxt", "location": str(manifest)}) == extension
    assert extension_directory(SimpleNamespace(source="dxt", location=manifest)) == extension
    assert extension_directory({"path": str(manifest)}) is None
    assert extension_directory({"source": "desktop", "location": manifest}) is None
    assert extension_directory({"source": "dxt", "location": manifest.with_name("other.json")}) is None
    assert extension_directory({"source": "dxt", "location": str(tmp_path / "manifest.json")}) is None
    assert extension_directory({"source": "dxt", "location": "Claude Extensions/id/manifest.json"}) is None
    link = tmp_path / "linked-extensions"
    link.symlink_to(extensions, target_is_directory=True)
    assert extension_directory({"source": "dxt", "location": link / extension.name / "manifest.json"}) is None


def test_manifest_identity_keeps_placeholders_literal(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    expanded = _config(args=[str(extension / "dist/index.js"), "/synthetic/root"])
    surface, _, reason = manifest_surface(expanded, extensions, extension)
    assert surface is None and reason is not None and "unmatched" in reason


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("env_keys", [["TOKEN", "PROFILE"], ["PROFILE", "TOKEN"], ["OTHER"], [], ["TOKEN"]])
def test_manifest_identity_requires_equal_environment_key_sets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected: bool, env_keys: list[str]
) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    document = json.loads(manifest.read_text())
    document["server"]["mcp_config"]["env"] = {"TOKEN": "never-retained", "PROFILE": "other-value"}
    manifest.write_text(json.dumps(document))
    settings = tmp_path / "Claude Extensions Settings"
    settings.mkdir()
    (settings / f"{extension.name}.json").write_text(
        json.dumps({"userConfig": {"allowed_directories": ["synthetic/project"]}})
    )
    config = _config().model_copy(update={"env_keys": env_keys})
    matches = set(env_keys) == {"TOKEN", "PROFILE"}
    if not matches:

        def forbidden_roots(*args: object, **kwargs: object) -> None:
            pytest.fail("mismatched manifest must not read settings")

        monkeypatch.setattr("redteam.chains.dxt._roots", forbidden_roots)
    server = resolve_configs(
        [config], dxt_dir=extensions, extensions={config.name: extension} if selected else {}
    )[0]
    assert server.tool_surface == ("KNOWN" if matches else "UNKNOWN")
    if matches:
        assert server.source == "dxt-manifest" and server.surface is not None
        assert server.roots == ("synthetic/project",)
    else:
        assert server.surface is None and server.roots == ()
        assert server.reason is not None and "unmatched" in server.reason
    rendered = to_json(build_report([server]))
    assert "never-retained" not in rendered and "other-value" not in rendered


@pytest.mark.parametrize("side", ["config", "manifest"])
@pytest.mark.parametrize("field", ["transport", "url"])
def test_manifest_identity_requires_stdio_and_absent_url(tmp_path: Path, side: str, field: str) -> None:
    extensions, extension = _extension(tmp_path)
    config = _config()
    value = "http" if field == "transport" else "https://example.invalid/mcp"
    if side == "config":
        config = config.model_copy(update={field: TransportType.HTTP if field == "transport" else value})
    else:
        manifest = extension / "manifest.json"
        document = json.loads(manifest.read_text())
        document["server"]["mcp_config"][field] = value
        manifest.write_text(json.dumps(document))
    surface, roots, reason = manifest_surface(config, extensions, extension)
    assert surface is None and roots == () and reason is not None and "unmatched" in reason


@pytest.mark.parametrize("command", [None, ""])
def test_manifest_identity_requires_a_nonempty_launch_command(tmp_path: Path, command: str | None) -> None:
    extensions, extension = _extension(tmp_path)
    config = _config().model_copy(update={"command": command})
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "server": {"mcp_config": {"command": command, "args": config.args}},
                "tools": [{"name": "write_file"}],
            }
        )
    )
    surface, _, reason = manifest_surface(config, extensions, extension)
    assert surface is None and reason is not None and "unmatched" in reason


@pytest.mark.parametrize("missing_pin", [False, True])
def test_trusted_and_withheld_pins_precede_matching_dxt_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_pin: bool
) -> None:
    from mcp_audit.models import ToolInfo
    from mcp_audit.pin_signing import generate_keypair
    from mcp_audit.pinning import PinStore

    extensions, _ = _extension(tmp_path)
    pins = tmp_path / "pins"
    trusted_keys = pins / "trusted-keys.yaml"
    key = generate_keypair(pins / "keys", trusted_keys)
    store = PinStore(
        pins / ".mcp-audit-pins.yaml", signing_key=key.private_key_path, trusted_keys_path=trusted_keys
    )
    config = _config()
    store.pin_server(config.name, [ToolInfo(name="pinned_tool")], config)
    if missing_pin:
        store.path.unlink()

    def forbidden_manifest(*args: object, **kwargs: object) -> object:
        raise AssertionError("pin resolution must finish before any DXT metadata read")

    monkeypatch.setattr("redteam.chains.pairs.manifest_surface", forbidden_manifest)
    server = resolve_configs([config], pins_dir=pins, dxt_dir=extensions)[0]
    if missing_pin:
        assert server.surface is None and "withheld" in (server.reason or "")
    else:
        assert server.source == "pin" and server.surface is not None
        assert [tool.name for tool in server.surface.tools] == ["pinned_tool"]


def test_versioned_playwright_and_local_identity() -> None:
    catalog = load_catalog()
    for args in (["@playwright/mcp@0.0.76"], ["-y", "@playwright/mcp@0.0.76"]):
        server = resolve_configs([_config("browser", "npx", args)])[0]
        assert server.surface is not None and server.surface.unverified
        assert len(server.surface.tools) >= 50
        tags = {label.tag for label in label_server(server.surface)}
        assert {
            "fetches_url",
            "runs_browser_script",
            "runs_command",
            "reads_file",
            "unknown",
        } == tags
    for version in ("0.0.75", "0.0.760", "unversioned"):
        package = "@playwright/mcp" + ("@" + version if version != "unversioned" else "")
        surface, reason = catalog_surface(_config("browser", "npx", [package]), catalog)
        assert surface is None and reason == f"catalog has 0.0.76, configured {version}"
    local = ServerSurface(server_name="machine-room", source="catalog")
    assert catalog_surface(
        _config("jobs", "bin/machine-room", ["mcp", "--session"]), {"local:machine-room": local}
    ) == (local, None)
    assert catalog_surface(_config("jobs", "machine-room", ["status"]), {"local:machine-room": local}) == (
        None,
        None,
    )
    assert resolve_configs([_config("unknown", "other-local", ["mcp"])])[0].surface is None


def test_unversioned_catalogs_do_not_match_versioned_package_identities() -> None:
    catalog = load_catalog()
    filesystem, reason = catalog_surface(
        _config("filesystem", "npx", ["-y", "@modelcontextprotocol/server-filesystem@3.0.0"]),
        catalog,
    )
    assert filesystem is None and reason is None
    git, reason = catalog_surface(_config("git", "uvx", ["mcp-server-git@1.2.3"]), catalog)
    assert git is None and reason is None


def test_machine_room_catalog_registration_and_job_start_label() -> None:
    server = resolve_configs([_config("jobs", "bin/machine-room", ["mcp", "--session", "synthetic"])])[0]
    assert server.source == "catalog" and server.surface is not None and server.surface.unverified
    surface = server.surface
    assert surface.provenance is not None and "source at commit" in surface.provenance
    assert [tool.name for tool in surface.tools] == ["reconcile", "start", "status", "stop"]
    start = next(tool for tool in surface.tools if tool.name == "start")
    assert start.input_schema["required"] == ["job", "claim", "cwd", "command"]
    labels = [label for label in label_server(surface) if label.tag == "runs_command"]
    assert {label.tool for label in labels} == {"start"}
    assert all(label.capability == "execute" for label in labels)
    # A status-only CLI invocation does not expose the MCP catalog.
    assert resolve_configs([_config("jobs", "machine-room", ["status"])])[0].surface is None


def test_real_style_dxt_and_catalog_ranking(tmp_path: Path) -> None:
    extensions, extension = _extension(tmp_path)
    manifest = extension / "manifest.json"
    data = json.loads(manifest.read_text())
    data["tools"] = [{"name": name} for name in ("create_directory", "edit_file", "move_file", "write_file")]
    manifest.write_text(json.dumps(data))
    chrome = ServerSurface(
        server_name="chrome-control",
        source="catalog",
        config=SurfaceConfig(command="chrome-control", args=[]),
        tools=[SurfaceTool(name="execute_javascript", description="Execute JavaScript in a browser page.")],
    )
    servers = resolve_configs(
        [
            _config(),
            _config("chrome-control", "chrome-control", []),
            _config("machine_room", "machine-room", ["mcp", "--session", "synthetic"]),
        ],
        {"chrome-control": chrome},
        dxt_dir=extensions,
    )
    browser = next(server for server in servers if server.name == "chrome-control")
    assert browser.surface is not None and browser.source == "explicit"
    assert {label.tag for label in label_server(browser.surface)} == {"runs_browser_script"}
    rows = build_report(servers)["ranked"]
    assert isinstance(rows, list) and rows
    assert (rows[0]["writer"], rows[0]["executor"], rows[0]["template"]) == (
        "Filesystem",
        "machine_room",
        "write-then-run",
    )
    assert all(row["executor"] != "chrome-control" for row in rows)


def test_xcodebuildmcp_without_version_matched_tool_docs_is_unknown() -> None:
    for args in (["xcodebuildmcp@2.6.2"], ["--yes", "xcodebuildmcp@2.6.2"]):
        server = resolve_configs([_config("build", "npx", args)])[0]
        assert server.surface is None and server.tool_surface == "UNKNOWN"
        assert server.reason is not None
        assert "No version-matched tool documentation" in server.reason
        assert "tag v2.6.2" in server.reason
        assert "unversioned https://xcodebuildmcp.com/docs/tools" in server.reason


def test_discovery_notes_in_both_reports() -> None:
    servers = DiscoveryServers(
        [],
        ["shadow-mcp source dxt: 2", "shadow-mcp collector error (details withheld)"],
        {"dxt": 2},
        ["synthetic failure"],
    )
    report = build_report(servers)
    assert report["discovery_notes"] == servers.notes
    for note in servers.notes:
        assert note in to_json(report) and note in to_markdown(report)


def test_write_run_reproducer_selected_after_unsupported_top(monkeypatch: pytest.MonkeyPatch) -> None:
    writer = ServerSurface(server_name="writer", source="fixture", tools=[SurfaceTool(name="write_file")])
    runner = ServerSurface(server_name="runner", source="fixture", tools=[SurfaceTool(name="run_command")])
    hook = ServerSurface(server_name="hook", source="fixture", tools=[SurfaceTool(name="git_commit")])
    servers = [
        ConfiguredServer("writer", writer, ("/synthetic/shared",)),
        ConfiguredServer("runner", runner),
        ConfiguredServer("hook", hook, ("/synthetic/shared",)),
    ]
    calls: list[str] = []

    def canary() -> ReproductionResult:
        calls.append("run")
        return ReproductionResult("SKIPPED", "nested sandbox unavailable")

    monkeypatch.setattr("redteam.chains.report.reproduce_write_then_run", canary)
    report = build_report(servers, reproduce=True)
    assert calls == ["run"]
    reproduction = report["reproduction"]
    assert isinstance(reproduction, dict) and reproduction["template"] == "write-then-run"
    assert reproduction["rank"] == 2
    assert "higher-ranked" in str(reproduction["selection_reason"])
    assert "Selected rank 2" in to_markdown(report)


def test_cli_dxt_dir_and_protected_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    extensions, extension = _extension(tmp_path)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mcpServers": {"Filesystem": {"command": "node", "args": _config().args}}}))
    assert main(["run", "--config", str(config), "--dxt-dir", str(extensions)]) == 0
    assert "DXT roots for Filesystem: unknown" in capsys.readouterr().out
    assert (
        main(
            [
                "run",
                "--config",
                str(config),
                "--dxt-dir",
                str(extensions),
                "--json",
                str(extension / "manifest.json"),
            ]
        )
        == 2
    )
