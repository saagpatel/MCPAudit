"""Synthetic acceptance contracts for the read-only fix preview."""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import _DISCOVERERS
from mcp_audit.pkgverify import RegistryClient

FILESYSTEM = "@modelcontextprotocol/server-filesystem"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)


def _config(tmp_path: Path, args: list[str], **fields: object) -> Path:
    config = tmp_path / "selected.json"
    config.write_text(json.dumps({"mcpServers": {"fixture": {"command": "npx", "args": args, **fields}}}))
    return config


def _run(config: Path, *options: str, server: str = "fixture") -> Result:
    return CliRunner().invoke(main, ["fix", server, "--config", str(config), *options])


def _patches(result: Result) -> list[dict[str, str]]:
    assert result.exit_code == 0, result.output
    assert "not written to disk" in result.output
    start = result.output.index("[\n")
    patches, _ = json.JSONDecoder().raw_decode(result.output[start:])
    assert isinstance(patches, list)
    return patches


@pytest.mark.parametrize("package", ["fixture-package", "@fixture/package"])
@pytest.mark.parametrize("version", [None, "1.2.3", "1.2.3-rc.1+build.2"])
def test_unpinned_package_preview(tmp_path: Path, package: str, version: str | None) -> None:
    config = _config(tmp_path, ["-y", package, "--token", "withheld-fixture-argument"])
    before = config.read_bytes()
    result = _run(config, *(["--package-version", version] if version is not None else []))
    assert _patches(result) == [
        {
            "op": "replace",
            "path": "/mcpServers/fixture/args/1",
            "value": f"{package}@{version or '<version you supply>'}",
        }
    ]
    assert "withheld-fixture-argument" not in result.output
    assert config.read_bytes() == before


@pytest.mark.parametrize("root", ["/", "$HOME"])
@pytest.mark.parametrize("version", ["", "@1.2.3"])
@pytest.mark.parametrize("path", [None, "$HOME/project"])
def test_filesystem_root_preview(tmp_path: Path, root: str, version: str, path: str | None) -> None:
    config = _config(tmp_path, ["-y", FILESYSTEM + version, root, "/already/narrow"])
    before = config.read_bytes()
    result = _run(config, *(["--path", path] if path is not None else []))
    patches = _patches(result)
    assert patches[-1] == {
        "op": "replace",
        "path": "/mcpServers/fixture/args/2",
        "value": path or "<narrower path you supply>",
    }
    assert len(patches) == (1 if version else 2)
    assert all(patch["path"] != "/mcpServers/fixture/args/3" for patch in patches)
    assert config.read_bytes() == before
    assert "symlinks are not checked" in result.output


def test_both_fixes_with_supplied_values_and_multiple_roots(tmp_path: Path) -> None:
    config = _config(tmp_path, ["-y", FILESYSTEM, "$HOME", "/"])
    result = _run(config, "--package-version", "1.2.3", "--path", str(Path.home() / "project"))
    patches = _patches(result)
    assert len(patches) == 3
    assert patches[0]["value"] == FILESYSTEM + "@1.2.3"
    assert [patch["path"] for patch in patches[1:]] == [
        "/mcpServers/fixture/args/2",
        "/mcpServers/fixture/args/3",
    ]
    assert all(patch["value"] == str(Path.home() / "project") for patch in patches[1:])


@pytest.mark.parametrize(
    "args",
    [
        ["-y", "fixture-package@1.2.3"],
        ["-y", "fixture-package@latest"],
        ["-y", "https://example.invalid/package"],
        ["--yes", "fixture-package"],
        ["--package", "fixture-package", "run"],
        ["-y", "./fixture-package"],
        ["-y"],
        [],
        ["-y", FILESYSTEM + "@1.2.3", "/already/narrow"],
    ],
)
def test_unsupported_cases_do_not_invent_fixes(tmp_path: Path, args: list[str]) -> None:
    result = _run(_config(tmp_path, args))
    assert result.exit_code == 0, result.output
    assert "No supported fix" in result.output
    assert "not written to disk" in result.output
    assert "[\n" not in result.output


@pytest.mark.parametrize("fields", [{"command": "sh"}, {"type": "http"}, {"url": "https://example.invalid"}])
def test_other_launchers_and_transports_are_unsupported(tmp_path: Path, fields: dict[str, str]) -> None:
    result = _run(_config(tmp_path, ["-y", FILESYSTEM, "/"], **fields))
    assert result.exit_code == 0
    assert "No supported fix" in result.output


@pytest.mark.parametrize("version", ["latest", "^1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3\n", "1.2.3;run"])
def test_version_must_be_exact(tmp_path: Path, version: str) -> None:
    result = _run(_config(tmp_path, ["-y", "fixture-package"]), "--package-version", version)
    assert result.exit_code == 2
    assert "supply an exact version" in result.output
    assert "[\n" not in result.output


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "$HOME",
        "$HOME/..",
        "$HOME/project/../../escape",
        "relative",
        "/outside",
        "/project\n",
        "/project/..",
        "/project/.",
        "//project",
    ],
)
def test_rejects_paths_that_do_not_narrow_home(tmp_path: Path, path: str) -> None:
    result = _run(_config(tmp_path, ["-y", FILESYSTEM, "$HOME"]), "--path", path)
    assert result.exit_code == 2
    assert "strict subdirectory" in result.output
    assert "[\n" not in result.output


def test_rejects_expanded_home_and_accepts_absolute_subdirectory(tmp_path: Path) -> None:
    config = _config(tmp_path, ["-y", FILESYSTEM + "@1.2.3", "/"])
    rejected = _run(config, "--path", str(Path.home()))
    assert rejected.exit_code == 2
    accepted = _run(config, "--path", "/workspace/project")
    assert _patches(accepted)[0]["value"] == "/workspace/project"


@pytest.mark.parametrize("options", [["--package-version", "1.2.3"], ["--path", "/workspace/project"]])
def test_inapplicable_supplied_options_are_errors(tmp_path: Path, options: list[str]) -> None:
    result = _run(_config(tmp_path, ["-y", "fixture-package@1.2.3"]), *options)
    assert result.exit_code == 1
    assert "No supported" in result.output
    assert "[\n" not in result.output


def test_requires_config_and_has_no_write_option(tmp_path: Path) -> None:
    config = _config(tmp_path, ["-y", "fixture-package"])
    missing = CliRunner().invoke(main, ["fix", "fixture"])
    assert missing.exit_code == 2
    assert "Missing option '--config'" in missing.output
    write = _run(config, "--write")
    assert write.exit_code == 2
    assert "No such option '--write'" in write.output
    help_result = CliRunner().invoke(main, ["fix", "--help"])
    assert help_result.exit_code == 0
    assert "--write" not in help_result.output


def test_selection_requires_one_entry_and_supports_exact_identity(tmp_path: Path) -> None:
    config = _config(tmp_path, ["-y", "fixture-package"])
    assert _run(config, server="missing").exit_code == 1
    assert _patches(_run(config, server="claude_code:workstation:fixture"))
    config.write_text(
        json.dumps(
            {
                "mcpServers": {"fixture": {"command": "npx", "args": ["-y", "fixture-package"]}},
                "projects": {
                    "/synthetic/project": {
                        "mcpServers": {"fixture": {"command": "npx", "args": ["-y", "other-package"]}}
                    }
                },
            }
        )
    )
    assert _run(config).exit_code == 1
    assert (
        _patches(_run(config, server="claude_code:project:fixture"))[0]["path"]
        == "/projects/~1synthetic~1project/mcpServers/fixture/args/1"
    )


@pytest.mark.parametrize("content", ["{", "[]", '{"mcpServers":{"fixture":{"args":42}}}'])
def test_config_errors_never_produce_partial_suggestions(tmp_path: Path, content: str) -> None:
    config = tmp_path / "selected.json"
    config.write_text(content)
    result = _run(config)
    assert result.exit_code == 1
    assert "Nothing written" in result.output
    assert "[\n" not in result.output


def test_missing_config_has_a_bounded_error(tmp_path: Path) -> None:
    result = _run(tmp_path / "missing.json")
    assert result.exit_code == 1
    assert "check --config" in result.output


def test_preview_never_discovers_connects_fetches_or_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(
        tmp_path,
        ["-y", FILESYSTEM, "/"],
        env={"FIXTURE_KEY": ""},
        headers={"Authorization": ""},
    )
    before = config.read_bytes()
    files = set(tmp_path.rglob("*"))

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("preview must only read the selected config")

    for discoverer in _DISCOVERERS.values():
        monkeypatch.setattr(discoverer, "config_paths", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    monkeypatch.setattr(RegistryClient, "_get_json", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    result = _run(config, "--package-version", "1.2.3", "--path", "/workspace/project")
    assert len(_patches(result)) == 2
    assert "FIXTURE_KEY" not in result.output
    assert "Authorization" not in result.output
    assert '"env"' not in result.output
    assert '"headers"' not in result.output
    assert config.read_bytes() == before
    assert set(tmp_path.rglob("*")) == files
