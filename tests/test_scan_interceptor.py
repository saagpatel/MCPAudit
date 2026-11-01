"""User-visible 3.0 interceptor behavior, using only synthetic inputs."""

from __future__ import annotations

import json
import shlex
from importlib.util import find_spec
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit import check_cli, cli, discovery


def test_legacy_adapter_module_is_removed() -> None:
    assert find_spec("mcp_audit.scan_cli") is None


@pytest.mark.parametrize(
    ("args", "replacement"),
    [
        ([], ["--include-discovered", "--connect-all"]),
        (["--skip-connect", "--json", "report.json"], ["--output-json", "report.json"]),
        (["--skip-connect", "--clients", "cursor,vscode"], ["--client", "cursor", "--client", "vscode"]),
        (["--config", "fixture.json", "--config-only"], ["--config", "fixture.json", "--config-only"]),
        (["--skip-connect", "--config", "fixture.json"], ["--include-discovered"]),
        (["--connect-project-configs"], ["--connect-all"]),
    ],
)
def test_refused_scan_prints_manual_replacement_without_any_execution(
    args: list[str], replacement: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("refused scan must not inspect sources or execute check")

    monkeypatch.setattr(check_cli, "review_sources", forbidden)
    monkeypatch.setattr(check_cli.check, "make_context", forbidden)
    monkeypatch.setattr(discovery, "discover_all_configs", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "home", forbidden)
    result = CliRunner().invoke(cli.main, ["scan", *args])
    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("scan: no exact check translation exists:")
    assert lines[1].startswith("scan: replacement command (not exact; review before running): ")
    printed = shlex.split(lines[1].split(": ", 2)[2])
    assert printed[:2] == ["mcp-audit", "check"]
    assert any(printed[i : i + len(replacement)] == replacement for i in range(len(printed)))
    if not args:
        assert printed == ["mcp-audit", "check", *replacement]


def test_refused_scan_never_prints_unsafe_argument_values(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("refused scan must not invoke check")

    monkeypatch.setattr(check_cli.check, "make_context", forbidden)
    result = CliRunner().invoke(
        cli.main, ["scan", "--skip-connect", "--ignore-reason", "token=synthetic-secret"]
    )
    assert result.exit_code == 2
    assert "synthetic-secret" not in result.output
    assert len(result.stderr.splitlines()) == 2


@pytest.mark.parametrize("help_flag", ["--help", "--help-all"])
def test_scan_is_registered_but_hidden_from_help(help_flag: str) -> None:
    result = CliRunner().invoke(cli.main, [help_flag])
    assert result.exit_code == 0
    assert not any(line.strip().startswith("scan ") for line in result.stdout.splitlines())
    direct = CliRunner().invoke(cli.main, ["scan", "--help"])
    assert direct.exit_code == 0
    assert direct.stderr == ""
    assert "--config-only" in direct.stdout


@pytest.mark.parametrize("policy_failure", [False, True])
def test_translated_scan_uses_check_stdout_card_and_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_failure: bool
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "fixture with spaces.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "never-launch", "args": ["/"]}}}')
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on:\n  config_health: high\n")
    if policy_failure:
        config.write_text('{"mcpServers": {"fixture": {"args": []}}}')
    card = tmp_path / "card.html"
    output = tmp_path / "report.sarif"
    common = [
        "--config",
        str(config),
        "--config-only",
        "--skip-connect",
        "--override-config",
        "/dev/null",
        "--color",
        "never",
        "--policy",
        str(policy),
        "--card",
        card.name,
        "--sarif",
        output.name,
    ]
    scan = CliRunner().invoke(cli.main, ["scan", *common])
    assert scan.exit_code == (2 if policy_failure else 0), scan.output
    assert len(scan.stderr.splitlines()) == 1
    printed = shlex.split(scan.stderr.strip().split(": ", 2)[2])
    assert printed[:2] == ["mcp-audit", "check"]
    scan_card = card.read_text()
    scan_sarif = json.loads(output.read_text())
    check = CliRunner().invoke(cli.main, printed[1:])
    assert check.exit_code == scan.exit_code
    assert check.stdout == scan.stdout
    assert check.stderr == ""
    assert card.read_text() == scan_card
    assert json.loads(output.read_text()) == scan_sarif
    assert f"Wrote {card.name}" in scan.stdout
    assert f"Wrote {output.name}" in scan.stdout
    assert "Preview" in scan.stdout
    assert "tools" in scan.stdout


def test_check_parser_rejects_translated_option_combination() -> None:
    result = CliRunner().invoke(
        cli.main,
        [
            "scan",
            "--config",
            "fixture.json",
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--names",
        ],
    )
    assert result.exit_code == 2
    assert result.stderr.splitlines()[0].startswith("scan: options map exactly")
    assert "--names and --previous require --card" in result.stderr
    assert "Scanned: no" in result.stderr
