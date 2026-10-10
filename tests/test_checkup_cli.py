"""Explicit synthetic CLI acceptance; no workstation discovery or connections."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery import _DISCOVERERS


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("explicit static card must not discover or connect")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    for discoverer in _DISCOVERERS.values():
        monkeypatch.setattr(discoverer, "discover", forbidden)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "synthetic-mcp.json"
    config.write_text(json.dumps({"mcpServers": {"private-fixture-server": {"command": "fixture"}}}))
    return config


@pytest.mark.parametrize("command", ["checkup", "scan"])
def test_card_alias_static_privacy_and_sticker(config: Path, command: str, tmp_path: Path) -> None:
    card = tmp_path / "card.html"
    args = [command, "--config", str(config), "--override-config", "/dev/null", "--card", str(card)]
    if command == "scan":
        args += ["--config-only", "--skip-connect"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    output = card.read_text()
    assert "Preview" in output
    assert "private-fixture-server" not in output
    assert str(config) not in output
    assert "**MCPAudit checkup · Preview" in result.output


def test_checkup_default_file_and_opt_in_names(config: Path) -> None:
    result = CliRunner().invoke(main, ["checkup", "--config", str(config), "--names"])
    assert result.exit_code == 0, result.output
    assert "private-fixture-server" in Path("checkup.html").read_text()


@pytest.mark.parametrize("command", ["checkup", "scan"])
def test_card_cannot_overwrite_config(config: Path, command: str) -> None:
    original = config.read_bytes()
    args = [command, "--config", str(config), "--card", str(config), "--override-config", "/dev/null"]
    if command == "scan":
        args += ["--config-only", "--skip-connect"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    assert "aliases" in result.output
    assert config.read_bytes() == original


def test_previous_errors_withhold_report_values(config: Path, tmp_path: Path) -> None:
    previous = tmp_path / "previous.json"
    previous.write_text('{"hostname": "private-fixture-marker"}')
    result = CliRunner().invoke(main, ["checkup", "--config", str(config), "--previous", str(previous)])
    assert result.exit_code == 1, result.output
    assert "private-fixture-marker" not in result.output
    assert not Path("checkup.html").exists()
