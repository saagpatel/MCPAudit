"""Option-only translation contracts and isolated legacy scan acceptance."""

from __future__ import annotations

import json
import shlex
from collections.abc import MutableMapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import cast

import click
import pytest
from click.testing import CliRunner

from mcp_audit import _core_cli, check_cli, cli, discovery, review_discovery
from mcp_audit.scan_translation import OPTION_TABLE, OptionTranslation, classify_scan_options

EXPLICIT: dict[str, object] = {
    "extra_config": "fixture.json",
    "config_only": True,
    "skip_connect": True,
    "override_config_path": "/dev/null",
}
SAFE_ARGS = ["--config", "fixture.json", "--config-only", "--skip-connect", "--override-config", "/dev/null"]


def test_table_is_frozen_and_covers_every_registered_scan_option() -> None:
    options = {option.opts[0]: option for option in _core_cli.scan.params if isinstance(option, click.Option)}
    assert set(OPTION_TABLE) == set(options)
    with _core_cli.scan.make_context("scan", []) as context:
        defaults = dict(context.params)
    for spelling, rule in OPTION_TABLE.items():
        assert rule.parameter == options[spelling].name
        assert rule.default == defaults[rule.parameter]
    with pytest.raises(TypeError):
        cast(MutableMapping[str, OptionTranslation], OPTION_TABLE)["--new"] = OPTION_TABLE["--config"]
    with pytest.raises(FrozenInstanceError):
        OPTION_TABLE["--config"].check_option = "--new"  # type: ignore[misc]


@pytest.mark.parametrize("client", ["claude_desktop", "vscode", "windsurf"])
def test_preserved_discovery_always_includes_discovered(client: str) -> None:
    options: dict[str, object] = {"skip_connect": True, "clients": client, "inject_check": True}
    result = classify_scan_options(options)
    assert result.coverage == "preserved"
    assert result.check_argv is not None
    assert "--include-discovered" in result.check_argv
    assert "--skip-connect" in result.check_argv
    assert "--inject-check" in result.check_argv
    with check_cli.check.make_context("check", list(result.check_argv[2:])) as context:
        assert context.params["include_discovered"] is True
        assert context.params["skip_connect"] is True


def test_explicit_config_only_is_intentional_narrowing_with_an_exact_command() -> None:
    result = classify_scan_options(EXPLICIT)
    assert result.coverage == "narrowed"
    assert result.check_argv == (
        "mcp-audit",
        "check",
        "--skip-connect",
        "--config",
        "fixture.json",
        "--config-only",
        "--override-config",
        "/dev/null",
    )
    assert "--include-discovered" not in result.check_argv
    assert shlex.split(result.notice().split(": ", 2)[2]) == list(result.check_argv)


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ({}, "connected coverage"),
        ({"extra_config": "fixture.json", "config_only": True}, "connected coverage"),
        ({"skip_connect": True, "inject_check": True}, "other project scopes"),
        ({"skip_connect": True, "clients": "claude_code"}, "other project scopes"),
        ({"skip_connect": True, "clients": "cursor"}, "Cursor project discovery"),
        ({"skip_connect": True, "clients": "vscode", "extra_config": "fixture.json"}, "overlapping sources"),
        ({**EXPLICIT, "json_output": "report.json"}, "--json PATH"),
        ({**EXPLICIT, "clients": "vscode,windsurf"}, "comma-separated"),
        ({**EXPLICIT, "clients": "unknown"}, "supported client"),
        ({**EXPLICIT, "new_option": None}, "frozen scan table"),
        ({**EXPLICIT, "override_config_path": None}, "default overrides"),
        ({**EXPLICIT, "connect_project_configs": True}, "connection selection"),
        ({**EXPLICIT, "canary_check": True}, "connection selection"),
        ({**EXPLICIT, "extra_config": None}, "requires --config"),
        ({**EXPLICIT, "skip_connect": "yes"}, "parsed boolean"),
        ({**EXPLICIT, "ignore_rules": ["MCP001"]}, "parsed repeated option"),
        ({**EXPLICIT, "timeout": object()}, "parsed option value"),
    ],
)
def test_coverage_loss_and_untranslatable_options_fail_closed(
    options: dict[str, object], reason: str
) -> None:
    result = classify_scan_options(options)
    assert result.coverage == "would-silently-shrink"
    assert result.check_argv is None
    assert reason in result.notice()
    assert "no exact check translation exists" in result.notice()
    assert len(result.notice().splitlines()) == 1


@pytest.mark.parametrize("skip_connect", [False, True])
def test_lost_sources_override_explicit_narrowing_and_connection_status(skip_connect: bool) -> None:
    result = classify_scan_options({**EXPLICIT, "skip_connect": skip_connect, "clients": "vscode,windsurf"})
    assert result.coverage == "would-silently-shrink"
    assert result.check_argv is None
    if not skip_connect:
        assert any("connected coverage" in reason for reason in result.reasons)


def test_classifier_never_reads_paths_or_runs_either_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("translation must use parsed options alone")

    monkeypatch.setattr(discovery, "discover_all_configs", forbidden)
    monkeypatch.setattr(review_discovery, "review_sources", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "exists", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "home", forbidden)
    assert classify_scan_options(EXPLICIT).coverage == "narrowed"
    assert classify_scan_options({"skip_connect": True}).coverage == "would-silently-shrink"
    assert classify_scan_options({"skip_connect": True, "clients": "vscode"}).coverage == "preserved"


@pytest.mark.parametrize(
    "spelling", sorted(set(OPTION_TABLE) - {"--json", "--canary-check", "--connect-project-configs"})
)
def test_exact_mapping_retains_each_option_and_is_accepted_by_check(spelling: str) -> None:
    rule = OPTION_TABLE[spelling]
    overrides: dict[str, object] = {"card": Path("card.html")}
    if rule.kind == "flag":
        overrides[rule.parameter] = True
    elif rule.kind == "repeat":
        overrides[rule.parameter] = (
            ("MCP001", "MCP002") if spelling == "--ignore" else ("fixture/tool", "fixture/other")
        )
    else:
        overrides[rule.parameter] = {
            "--clients": "vscode",
            "--sarif-profile": "extended",
            "--color": "never",
        }.get(
            spelling,
            2
            if isinstance(rule.default, int) or spelling in ("--pin-min-sequence", "--canary-identities")
            else "value with spaces",
        )
    with _core_cli.scan.make_context("scan", list(SAFE_ARGS)) as context:
        options: dict[str, object] = dict(context.params)
    result = classify_scan_options({**options, **overrides})
    assert result.check_argv is not None, result.notice()
    assert rule.check_option in result.check_argv
    if rule.kind != "flag":
        value = overrides[rule.parameter]
        expected = list(value) if isinstance(value, tuple) else [str(value)]
        actual = [
            result.check_argv[index + 1]
            for index, arg in enumerate(result.check_argv)
            if arg == rule.check_option
        ]
        assert actual == expected
    with check_cli.check.make_context("check", list(result.check_argv[2:])):
        pass


def test_shell_quoting_round_trips_without_interpreting_argument_text() -> None:
    path = Path("fixture with 'quotes' $(literal);.json")
    result = classify_scan_options({**EXPLICIT, "extra_config": path, "ignore_reason": "reviewer's choice"})
    assert result.check_argv is not None
    assert shlex.split(result.notice().split(": ", 2)[2]) == list(result.check_argv)
    assert str(path) in result.check_argv


@pytest.mark.parametrize(
    "argument", ["line\nbreak", "tab\tvalue", "escape\x1b[31m", "bidi\u202evalue", "token=synthetic-secret"]
)
def test_unsafe_argument_values_are_withheld_without_echoing_them(argument: str) -> None:
    result = classify_scan_options({**EXPLICIT, "ignore_reason": argument})
    assert result.check_argv is None
    assert argument not in result.notice()
    assert "cannot be safely printed" in result.notice()
    assert len(result.notice().splitlines()) == 1


@pytest.mark.parametrize("exit_code", [0, 1, 2, 130])
@pytest.mark.parametrize("untranslatable", [False, True])
def test_notice_is_one_stderr_line_and_never_changes_legacy_execution_or_exit(
    exit_code: int, untranslatable: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[object, ...]] = []

    async def legacy(*args: object, **kwargs: object) -> None:
        calls.append(args)
        click.echo("legacy output")
        raise SystemExit(exit_code)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the notice must not invoke check")

    monkeypatch.setattr(_core_cli, "_run_scan", legacy)
    monkeypatch.setattr(check_cli, "run_scan", forbidden)
    args = ["scan", *SAFE_ARGS, *(["--json", "report.json"] if untranslatable else [])]
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == exit_code, result.output
    assert result.stdout == "legacy output\n"
    assert len(result.stderr.splitlines()) == 1
    assert ("no exact" if untranslatable else "exact check translation:") in result.stderr
    assert len(calls) == 1
    assert calls[0][0] == ("report.json" if untranslatable else None)
    assert calls[0][3] is True  # skip-connect retains its original engine position


def test_synthetic_scan_and_its_translation_select_the_same_servers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    monkeypatch.chdir(tmp_path)
    fixture = tmp_path / "fixture with spaces.json"
    fixture.write_text(
        json.dumps({"mcpServers": {"fixture": {"command": "never-launch-fixture", "args": []}}})
    )
    scan_sarif = tmp_path / "scan.sarif"
    scan_args = [
        "scan",
        "--config",
        str(fixture),
        "--config-only",
        "--skip-connect",
        "--override-config",
        "/dev/null",
        "--inject-check",
        "--sarif",
        str(scan_sarif),
    ]
    scan_result = CliRunner().invoke(cli.main, scan_args)
    assert scan_result.exit_code == 0, scan_result.output
    assert len(scan_result.stderr.splitlines()) == 1
    translation = shlex.split(scan_result.stderr.strip().split(": ", 2)[2])
    assert translation[:2] == ["mcp-audit", "check"]
    check_sarif = tmp_path / "check.sarif"
    translation[translation.index("--sarif") + 1] = str(check_sarif)
    check_result = CliRunner().invoke(cli.main, translation[1:])
    assert check_result.exit_code == 0, check_result.output
    assert json.loads(scan_sarif.read_text()) == json.loads(check_sarif.read_text())


def test_invalid_config_only_still_emits_notice_and_keeps_existing_exit() -> None:
    result = CliRunner().invoke(cli.main, ["scan", "--config-only", "--skip-connect"])
    assert result.exit_code == 1
    assert result.stderr.splitlines()[0].startswith("scan: no exact check translation exists:")
    assert result.stderr.splitlines()[1] == "Error: --config-only requires --config PATH."
