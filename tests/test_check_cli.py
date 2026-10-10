"""Fixture-only contracts for the additive safe review CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from click.testing import CliRunner

from mcp_audit import artifact_paths, check_cli, cli, engine, scan_cli, suppressions
from mcp_audit.check_cli import demo
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery.vscode import VSCodeDiscoverer
from mcp_audit.review_discovery import MAX_CONFIG_BYTES, review_sources

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "examples/sandbox/fixtures/synthetic-mcp-config.json"


@pytest.fixture(autouse=True)
def isolated_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)


def _config(path: Path, name: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {name: {"command": "never-launch-this-fixture"}}}))
    return path


@pytest.fixture(params=["claude", "vscode"])
def general_settings(request: pytest.FixtureRequest) -> Path:
    path = (
        Path.home() / ".claude.json" if request.param == "claude" else VSCodeDiscoverer().config_paths()[-1]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _normalized(payload: str) -> dict[str, object]:
    report = cast(dict[str, object], json.loads(payload))
    report.pop("scan_timestamp")
    report.pop("scan_duration_seconds")
    return report


def test_bare_empty_home_spawns_nothing_and_offers_next_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static review must never spawn or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    result = CliRunner().invoke(cli.main, [])
    assert result.exit_code == 0, result.output
    assert result.output.startswith("No MCP servers found")
    assert "PARTIAL" not in result.output
    assert "mcp-audit demo" in result.output
    assert "mcp-audit check --config" in result.output
    assert "NOT CHECKED" in result.output
    assert not (Path.home() / ".mcp-audit-pins.yaml").exists()


@pytest.mark.parametrize("args", [["check", "--json"], ["--json"]])
def test_empty_home_has_no_config_findings_or_partial_coverage(args: list[str]) -> None:
    sources = review_sources()
    assert not sources.errors
    assert sources.paths
    assert all(status == "absent" for _, status in sources.paths)
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["servers_discovered"] == 0
    assert payload["config_health_findings"] == []
    assert payload["coverage"]["config_health"]["state"] == "complete"
    assert all(entry["state"] != "partial" for entry in payload["coverage"].values())


def test_one_valid_home_config_with_other_clients_absent_is_healthy() -> None:
    config = _config(Path.home() / ".cursor/mcp.json")
    sources = review_sources()
    assert not sources.errors
    assert (str(config), "checked: 1 entries") in sources.paths
    assert all(path == str(config) or status == "absent" for path, status in sources.paths)
    result = CliRunner().invoke(cli.main, ["check", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["servers_discovered"] == 1
    assert payload["config_health_findings"] == []
    assert payload["coverage"]["config_health"]["state"] == "complete"


@pytest.mark.parametrize("present", [False, True])
def test_denied_opens_only_diagnose_existing_configs(monkeypatch: pytest.MonkeyPatch, present: bool) -> None:
    import os

    if present:
        _config(Path.home() / ".cursor/mcp.json")

    def denied_open(*args: object, **kwargs: object) -> int:
        raise PermissionError("synthetic read denial")

    monkeypatch.setattr(os, "open", denied_open)
    result = CliRunner().invoke(cli.main, ["check", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    findings = payload["config_health_findings"]
    if present:
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "config_parse_failure"
        assert findings[0]["details"] == ["unreadable config: PermissionError"]
        assert payload["coverage"]["config_health"]["state"] == "partial"
    else:
        assert findings == []
        assert payload["coverage"]["config_health"]["state"] == "complete"


@pytest.mark.parametrize(
    "fixture",
    [
        "examples/sandbox/fixtures/synthetic-mcp-config.json",
        "tests/fixtures/claude_desktop_config.json",
        "docs/assets/hero-demo-config.json",
        "tests/fixtures/config_health/shell_remote_arg_config.json",
    ],
)
def test_check_matches_legacy_static_scan(fixture: str, tmp_path: Path) -> None:
    output = tmp_path / "scan.json"
    scan = CliRunner().invoke(
        cli.main,
        [
            "scan",
            "--config",
            str(ROOT / fixture),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--json",
            str(output),
        ],
    )
    check = CliRunner().invoke(cli.main, ["check", "--config", str(ROOT / fixture), "--json"])
    assert scan.exit_code == check.exit_code == 0, scan.output + check.output
    assert _normalized(check.stdout) == _normalized(output.read_text())


def test_explicit_config_never_discovers_or_loads_saved_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path / "selected.json")
    _config(Path.home() / ".cursor/mcp.json", "unselected")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("saved settings and legacy discovery must not be consulted")

    monkeypatch.setattr(engine, "discover_all_configs", forbidden)
    monkeypatch.setattr(scan_cli, "load_override_config", forbidden)
    monkeypatch.setattr(Path, "home", forbidden)
    result = CliRunner().invoke(cli.main, ["check", "--config", str(config), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["servers_discovered"] == 1


def test_include_discovered_is_explicit_and_still_static(tmp_path: Path) -> None:
    config = _config(tmp_path / "selected.json")
    _config(Path.home() / ".cursor/mcp.json", "discovered")
    result = CliRunner().invoke(
        cli.main, ["check", "--config", str(config), "--include-discovered", "--json"]
    )
    payload = json.loads(result.stdout)
    assert result.exit_code == 0, result.output
    assert payload["servers_discovered"] == 2
    assert payload["connection_mode"] == "skipped"


def test_json_stdout_is_parseable_with_artifacts_and_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on:\n  coverage: true\n")
    paths = {name: tmp_path / f"report.{name}" for name in ("json", "sarif", "html")}
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(SANDBOX),
            "--json",
            "--policy",
            str(policy),
            "--output-json",
            str(paths["json"]),
            "--sarif",
            str(paths["sarif"]),
            "--html",
            str(paths["html"]),
        ],
    )
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout) == json.loads(paths["json"].read_text())
    assert "Wrote" not in result.stdout
    assert "Wrote" in result.stderr
    assert json.loads(paths["sarif"].read_text())["version"] == "2.1.0"
    assert "<html" in paths["html"].read_text()


def test_check_clients_accept_hyphen_and_underscore_aliases() -> None:
    _config(Path.home() / ".cursor/mcp.json", "cursor-fixture")
    _config(Path.home() / ".claude.json", "claude-fixture")
    for alias in ("claude-code", "claude_code"):
        result = CliRunner().invoke(cli.main, ["check", "--client", alias, "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["servers_discovered"] == 1
        assert payload["audits"][0]["server"]["client"] == "claude_code"


def test_inspect_json_output_and_repeatable_client_filters(tmp_path: Path) -> None:
    _config(Path.home() / ".cursor/mcp.json", "cursor-fixture")
    _config(Path.home() / ".claude.json", "claude-fixture")
    output = tmp_path / "inspect.json"
    result = CliRunner().invoke(
        cli.main,
        ["inspect", "--client", "cursor", "--client", "claude-code", "--json", "--output-json", str(output)],
    )
    assert result.exit_code == 0, result.output
    assert "Wrote" not in result.stdout
    payload = json.loads(result.stdout)
    assert {item["identity"].split(":", 1)[0] for item in payload["servers"]} == {
        "cursor",
        "claude_code",
    }
    assert json.loads(output.read_text()) == payload


def test_checkup_supports_both_audit_report_json_modes(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    card = tmp_path / "card.html"
    result = CliRunner().invoke(
        cli.main,
        ["checkup", "--config", str(SANDBOX), "--card", str(card), "--json", "--output-json", str(output)],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == json.loads(output.read_text())
    assert "Wrote" not in result.stdout
    assert "<html" in card.read_text()


def test_check_error_includes_recovery_state_and_option_typo_suggestion() -> None:
    missing = CliRunner().invoke(cli.main, ["check", "--config", "missing-synthetic-config.json"])
    assert missing.exit_code == 1
    for section in ("What failed:", "Where:", "Recovery:", "Scanned: no", "Written: none", "Exit code: 1"):
        assert section in missing.output
    typo = CliRunner().invoke(cli.main, ["check", "--detials"])
    assert typo.exit_code == 2
    assert "Did you mean" in typo.output


@pytest.mark.parametrize(
    ("command", "failed_flag"),
    [
        ("check", "--output-json"),
        ("check", "--sarif"),
        ("check", "--html"),
        ("check", "--card"),
        ("checkup", "--output-json"),
        ("checkup", "--card"),
    ],
)
def test_artifact_write_failure_identifies_destination_and_prior_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, failed_flag: str
) -> None:
    flags = (
        ("--output-json", "--sarif", "--html", "--card")
        if command == "check"
        else (
            "--output-json",
            "--card",
        )
    )
    outputs = {flag: tmp_path / flag.removeprefix("--") for flag in flags}
    write_text = Path.write_text

    def denied(
        path: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        if path == outputs[failed_flag]:
            raise PermissionError("synthetic write denial")
        return write_text(path, data, encoding=encoding, errors=errors, newline=newline)

    monkeypatch.setattr(Path, "write_text", denied)
    args = [command, "--config", str(SANDBOX), "--json"]
    for flag, path in outputs.items():
        args.extend([flag, str(path)])
    result = CliRunner().invoke(cli.main, args)

    assert result.exit_code == 1, result.output
    assert not result.stdout
    assert "What failed: synthetic write denial" in result.stderr
    assert f"Where: {failed_flag} destination\n" in result.stderr
    assert "Recovery:" in result.stderr
    assert "Scanned: yes" in result.stderr
    assert "Exit code: 1" in result.stderr
    prior = list(outputs.values())[: flags.index(failed_flag)]
    assert f"Written: {', '.join(map(str, prior)) if prior else 'none'}\n" in result.stderr
    assert all(path.exists() == (path in prior) for path in outputs.values())


def test_post_processing_failure_is_not_reported_as_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def invalid(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic post-processing failure")

    monkeypatch.setattr(suppressions, "apply_suppressions", invalid)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        cli.main, ["check", "--config", str(SANDBOX), "--output-json", str(output), "--json"]
    )
    assert result.exit_code == 1, result.output
    assert "Where: report post-processing\n" in result.stderr
    assert "Scanned: yes" in result.stderr
    assert "Written: none" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("command", ["check", "checkup", "inspect"])
def test_artifact_input_alias_has_recovery_details_without_modifying_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    config = tmp_path / "synthetic.json"
    before = SANDBOX.read_bytes()
    config.write_bytes(before)
    card = tmp_path / "card.html"

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid artifact destinations must be rejected before scanning")

    monkeypatch.setattr(check_cli, "run_scan", forbidden)
    args = [command, "--config", str(config), "--output-json", str(config), "--json"]
    if command == "checkup":
        args.extend(["--card", str(card)])
    result = CliRunner().invoke(cli.main, args)

    assert result.exit_code == 2, result.output
    assert not result.stdout
    assert "What failed:" in result.stderr
    assert "--output-json" in result.stderr
    assert "aliases an input file" in result.stderr
    assert "Where:" in result.stderr
    assert "Recovery:" in result.stderr
    assert f"Scanned: {'yes' if command == 'inspect' else 'no'}" in result.stderr
    assert "Written: none" in result.stderr
    assert "Exit code: 2" in result.stderr
    assert config.read_bytes() == before
    assert not card.exists()


@pytest.mark.parametrize("command", ["check", "checkup", "inspect"])
@pytest.mark.parametrize("failed_path", ["input", "output"])
def test_artifact_path_verification_failure_has_recovery_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, failed_path: str
) -> None:
    output = tmp_path / "report.json"
    card = tmp_path / "card.html"
    identity = artifact_paths._identity

    def denied(path: Path) -> tuple[Path, tuple[int, int] | None]:
        if path == (SANDBOX if failed_path == "input" else output):
            raise PermissionError("synthetic path verification denial")
        return identity(path)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("unverifiable artifact paths must be rejected before scanning")

    monkeypatch.setattr(artifact_paths, "_identity", denied)
    monkeypatch.setattr(check_cli, "run_scan", forbidden)
    args = [command, "--config", str(SANDBOX), "--output-json", str(output), "--json"]
    if command == "checkup":
        args.extend(["--card", str(card)])
    result = CliRunner().invoke(cli.main, args)

    assert result.exit_code == 2, result.output
    assert not result.stdout
    expected = "input paths" if failed_path == "input" else "output path"
    assert f"Cannot verify {expected}: PermissionError" in result.stderr
    assert "What failed:" in result.stderr
    assert "--output-json" in result.stderr
    assert "Where:" in result.stderr
    assert "Recovery:" in result.stderr
    assert f"Scanned: {'yes' if command == 'inspect' else 'no'}" in result.stderr
    assert "Written: none" in result.stderr
    assert "Exit code: 2" in result.stderr
    assert not output.exists()
    assert not card.exists()


def test_bare_json_and_details_and_grouped_help() -> None:
    result = CliRunner().invoke(cli.main, ["--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["servers_discovered"] == 0
    details = CliRunner().invoke(cli.main, ["--details"])
    assert details.exit_code == 0, details.output
    assert "absent:" in details.output
    for args in (["--help"], ["--help-all"]):
        help_result = CliRunner().invoke(cli.main, args)
        assert help_result.exit_code == 0
        for heading in ("Everyday", "Integrations", "Advanced"):
            assert heading in help_result.output
        assert "scan" in help_result.output
    ambiguous = CliRunner().invoke(cli.main, ["--json", "scan"])
    assert ambiguous.exit_code == 2


def test_demo_uses_exact_bundled_sandbox_fixture_and_no_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("demo must not discover or connect")

    monkeypatch.setattr(Path, "home", forbidden)
    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    bundled = ROOT / "src/mcp_audit/fixtures/demo-mcp-config.json"
    assert bundled.read_bytes() == SANDBOX.read_bytes()
    result = CliRunner().invoke(cli.main, [demo.name or "demo"])
    assert result.exit_code == 0, result.output
    assert "bundled examples/sandbox synthetic fixture" in result.output
    assert "config-only" in result.output
    assert "5 entries" in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["check", "--connect"],
        ["check", "--server", "cursor:project:fixture"],
        ["check", "--connect", "--server", "cursor:project:missing"],
    ],
)
def test_connection_requires_unambiguous_explicit_identity(args: list[str]) -> None:
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 1, result.output


def test_selected_connection_uses_only_local_fixture(tmp_path: Path) -> None:
    (Path.home() / ".claude.json").write_text('{"theme":"dark"}')
    settings = VSCodeDiscoverer().config_paths()[-1]
    settings.parent.mkdir(parents=True)
    settings.write_text('{"editor.fontSize":14}')
    config = tmp_path / "local.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "selected": {
                        "command": sys.executable,
                        "args": [str(ROOT / "tests/fixtures/mock_server.py")],
                    },
                    "never-selected": {"command": "never-launch-this-fixture"},
                }
            }
        )
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--include-discovered",
            "--connect",
            "--server",
            "claude_code:workstation:selected",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["servers_discovered"] == payload["servers_connected"] == 1
    assert payload["audits"][0]["server"]["name"] == "selected"
    assert "Configured code may execute" in result.stderr


@pytest.mark.parametrize("contents", ["{}", '{"editor.fontSize":14}'])
def test_discovered_general_settings_without_mcp_are_healthy(
    tmp_path: Path, general_settings: Path, contents: str
) -> None:
    general_settings.write_text(contents)
    _config(tmp_path / ".mcp.json", "selected")
    sources = review_sources()
    assert not sources.errors
    assert [server.name for server in sources.servers] == ["selected"]
    assert (str(general_settings), "checked: 0 entries") in sources.paths
    result = CliRunner().invoke(cli.main, ["check", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["servers_discovered"] == 1
    assert not payload["config_health_findings"]


@pytest.mark.parametrize("contents", ["{}", '{"editor.fontSize":14}'])
def test_explicit_general_settings_without_mcp_remain_unsupported(
    general_settings: Path, contents: str
) -> None:
    general_settings.write_text(contents)
    with pytest.raises(ValueError, match="no server map found"):
        review_sources(general_settings)


@pytest.mark.parametrize("contents", ["{bad json", "[]", " ", '{"mcpServers":null}', '{"mcpServers":[]}'])
def test_malformed_general_settings_still_block_selection(
    tmp_path: Path, general_settings: Path, contents: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    general_settings.write_text(contents)
    config = _config(tmp_path / "selected.json", "selected")
    assert review_sources().errors

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("config diagnostics must block connections")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--include-discovered",
            "--connect",
            "--server",
            "claude_code:workstation:selected",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "exactly one server with no config diagnostics" in result.output


@pytest.mark.parametrize("path", [".mcp.json", ".vscode/mcp.json", ".cursor/mcp.json"])
def test_discovered_dedicated_config_without_mcp_remains_unsupported(tmp_path: Path, path: str) -> None:
    config = tmp_path / path
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("{}")
    assert any("no MCP server map" in error.reason for error in review_sources().errors)


def test_duplicate_identity_or_diagnostics_reject_before_connection(tmp_path: Path) -> None:
    selected = _config(tmp_path / "explicit.json")
    _config(Path.home() / ".claude.json")
    for corrupt in (False, True):
        if corrupt:
            (Path.home() / ".claude.json").write_text("{bad json")
        result = CliRunner().invoke(
            cli.main,
            [
                "check",
                "--config",
                str(selected),
                "--include-discovered",
                "--connect",
                "--server",
                "claude_code:workstation:fixture",
            ],
        )
        assert result.exit_code == 1, result.output
        assert "exactly one server with no config diagnostics" in result.output


def test_discovery_limits_and_project_scopes_are_visible(tmp_path: Path) -> None:
    data = {
        "mcpServers": {"global": {"command": "fixture"}},
        "projects": {
            str(tmp_path): {"mcpServers": {"current": {"command": "fixture"}}},
            "/synthetic/unrelated-project": {"mcpServers": {"other": {"command": "fixture"}}},
        },
    }
    (Path.home() / ".claude.json").write_text(json.dumps(data))
    _config(tmp_path / ".cursor/mcp.json", "project-cursor")
    result = CliRunner().invoke(cli.main, ["inspect", "--details"])
    assert result.exit_code == 0, result.output
    assert "claude_code:workstation:global" in result.output
    assert "claude_code:project:current" in result.output
    assert "cursor:project:project-cursor" in result.output
    assert ":other" not in result.output
    assert "skipped other project scopes" in result.output
    assert "Unsupported source: Codex" in result.output
    assert "absent:" in result.output


def test_symlinks_skipped_by_discovery_but_explicit_selection_allowed(tmp_path: Path) -> None:
    target = _config(tmp_path / "target.json")
    cursor = Path.home() / ".cursor/mcp.json"
    cursor.parent.mkdir()
    cursor.symlink_to(target)
    sources = review_sources()
    assert not sources.servers
    assert any("symlink skipped" in error.reason for error in sources.errors)
    assert len(review_sources(cursor).servers) == 1


@pytest.mark.parametrize(
    "contents",
    [
        "{bad json",
        " ",
        "{}",
        "[" * 65 + "0" + "]" * 65,
        "// comment\r" + "[" * 65 + "0" + "]" * 65,
        " " * (MAX_CONFIG_BYTES + 1),
    ],
)
def test_explicit_invalid_or_unbounded_config_is_setup_error(tmp_path: Path, contents: str) -> None:
    config = tmp_path / "invalid.json"
    config.write_text(contents)
    result = CliRunner().invoke(cli.main, ["check", "--config", str(config), "--json"])
    assert result.exit_code == 1, result.output
    assert not result.stdout


def test_unreadable_or_malformed_discovered_source_is_partial(tmp_path: Path) -> None:
    path = Path.home() / ".cursor/mcp.json"
    path.parent.mkdir()
    path.write_text("{malformed")
    result = CliRunner().invoke(cli.main, ["check"])
    assert result.exit_code == 0, result.output
    assert "PARTIAL" in result.output
    details = CliRunner().invoke(cli.main, ["inspect", "--details"])
    assert "skipped:" in details.output


def test_special_file_and_parent_symlink_are_skipped(tmp_path: Path) -> None:
    import os

    cursor = Path.home() / ".cursor/mcp.json"
    cursor.parent.mkdir()
    os.mkfifo(cursor)
    assert any("not a regular file" in error.reason for error in review_sources().errors)
    cursor.unlink()
    cursor.parent.rmdir()
    target = tmp_path / "linked-directory"
    _config(target / "mcp.json")
    cursor.parent.symlink_to(target, target_is_directory=True)
    assert any("symlink skipped" in error.reason for error in review_sources().errors)


def test_other_project_requires_explicit_project_selection(tmp_path: Path) -> None:
    other = tmp_path / "other-project"
    other.mkdir()
    config = Path.home() / ".claude.json"
    config.write_text(
        json.dumps(
            {
                "projects": {
                    str(other): {"mcpServers": {"other": {"command": "fixture"}}},
                }
            }
        )
    )
    assert not review_sources().servers
    sources = review_sources(project=other)
    assert [server.name for server in sources.servers] == ["other"]


@pytest.mark.parametrize("relative", [False, True])
def test_project_dot_components_match_normalized_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: bool
) -> None:
    project = tmp_path / "selected-project"
    child = project / "child"
    child.mkdir(parents=True)
    (Path.home() / ".claude.json").write_text(
        json.dumps({"projects": {str(project): {"mcpServers": {"saved": {"command": "fixture"}}}}})
    )
    _config(project / ".mcp.json", "shared")
    _config(project / ".vscode/mcp.json", "vscode")
    _config(project / ".cursor/mcp.json", "cursor")
    monkeypatch.chdir(child)
    selected = Path("..") if relative else child / ".."
    normalized = review_sources(project=project)
    sources = review_sources(project=selected)
    assert not sources.errors
    assert {server.name for server in sources.servers} == {"saved", "shared", "vscode", "cursor"}
    assert sources == normalized
    result = CliRunner().invoke(cli.main, ["inspect", "--project", str(selected)])
    assert result.exit_code == 0, result.output
    assert "claude_code:project:saved" in result.output


def test_project_dot_normalization_preserves_symlink_rejection(tmp_path: Path) -> None:
    target = tmp_path / "target"
    _config(target / ".mcp.json")
    (target / "child").mkdir()
    project = tmp_path / "linked-project"
    project.symlink_to(target, target_is_directory=True)
    sources = review_sources(project=project / "child" / "..")
    assert not sources.servers
    assert any(error.reason.startswith("symlink skipped") for error in sources.errors)
    assert (str(project / ".mcp.json"), "skipped: symlink skipped; select it explicitly with --config") in (
        sources.paths
    )


def test_selected_null_project_is_diagnostic_and_blocks_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = Path.home() / ".claude.json"
    config.write_text(json.dumps({"projects": {str(tmp_path): None}}))
    _config(tmp_path / ".mcp.json", "selected")
    sources = review_sources()
    assert [server.name for server in sources.servers] == ["selected"]
    assert [error.reason for error in sources.errors] == ["project entry is not an object"]
    assert not any("skipped other project scopes" in status for _, status in sources.paths)
    result = CliRunner().invoke(cli.main, ["check", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert any(
        "project entry is not an object" in finding["summary"]
        for finding in payload["config_health_findings"]
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("selected null project must block connections")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    result = CliRunner().invoke(cli.main, ["check", "--connect", "--server", "claude_code:project:selected"])
    assert result.exit_code == 1, result.output
    assert "exactly one server with no config diagnostics" in result.output

    # A null entry outside the selected scope must still be skipped.
    config.write_text(json.dumps({"projects": {"/synthetic/unselected-project": None}}))
    sources = review_sources()
    assert not sources.errors
    assert any("skipped other project scopes" in status for _, status in sources.paths)


def test_cursor_explicit_format_matches_scan_and_home_stays_workstation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path / ".cursor/mcp.json")
    assert review_sources(config).servers[0].scope == "workstation"
    assert review_sources().servers[0].scope == "project"
    home = Path.home()
    _config(home / ".cursor/mcp.json", "home-cursor")
    monkeypatch.chdir(home)
    sources = review_sources()
    assert [server.scope for server in sources.servers] == ["workstation"]


def test_details_retains_config_diagnostics() -> None:
    result = CliRunner().invoke(cli.main, ["check", "--config", str(SANDBOX), "--details"])
    assert result.exit_code == 0, result.output
    assert "shell wrapper" in result.output
    assert "checked: 5 entries" in result.output


def test_malformed_policy_and_artifact_failure_are_setup_errors(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on: [")
    result = CliRunner().invoke(
        cli.main, ["check", "--config", str(SANDBOX), "--policy", str(policy), "--json"]
    )
    assert result.exit_code == 1, result.output
    assert not result.stdout
    output = tmp_path / "missing-directory/report.json"
    result = CliRunner().invoke(
        cli.main, ["check", "--config", str(SANDBOX), "--output-json", str(output), "--json"]
    )
    assert result.exit_code == 1, result.output
    assert not result.stdout
