"""Execute the Action step against a recording CLI, never a real config scan."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import check_cli, cli
from mcp_audit.connector import ServerConnector

ROOT = Path(__file__).resolve().parents[1]
RunAction = Callable[..., tuple[subprocess.CompletedProcess[str], list[list[str]], str]]


@pytest.fixture
def run_action(tmp_path: Path) -> RunAction:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "mcp-audit"
    shim.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "with pathlib.Path(os.environ['ARGV_LOG']).open('a') as log:\n"
        "    log.write(json.dumps(args) + '\\n')\n"
        "if args == ['check', '--help']:\n"
        "    expanded = os.environ['CAPABILITY'] == 'expanded'\n"
        "    print('  --include-discovered\\n  --output-json FILE')\n"
        "    if expanded:\n"
        "        print('  --inject-check\\n  --connect-all')\n"
        "    raise SystemExit(int(os.environ.get('HELP_CODE', '0')))\n"
        "raise SystemExit(int(os.environ.get('SCAN_CODE', '0')))\n"
    )
    shim.chmod(0o755)
    (bin_dir / "python").symlink_to(sys.executable)
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    script = step["run"]
    assert isinstance(script, str)

    def run(**inputs: str) -> tuple[subprocess.CompletedProcess[str], list[list[str]], str]:
        log = tmp_path / "argv.jsonl"
        output = tmp_path / "outputs"
        log.unlink(missing_ok=True)
        output.unlink(missing_ok=True)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "ARGV_LOG": str(log),
            "GITHUB_OUTPUT": str(output),
            "MCP_AUDIT_ACTION_PATH": str(ROOT),
            "CAPABILITY": "expanded",
            "SKIP_CONNECT": "true",
            "CLIENTS": "",
            "CONFIG": "",
            "POLICY": "",
            "SARIF": "mcp-audit.sarif",
            "JSON": "",
            "EXTRA_ARGS": "",
            **inputs,
        }
        result = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        return result, calls, output.read_text()

    return run


@pytest.mark.parametrize(
    ("version", "capability", "grammar"),
    [
        ("2.0.0", "old", "scan"),
        ("2.11.0", "old", "scan"),
        ("2.12.0", "expanded", "check"),
        ("3.0.0", "expanded", "check"),
    ],
)
def test_dispatch_uses_installed_capability(
    run_action: RunAction, version: str, capability: str, grammar: str
) -> None:
    result, calls, outputs = run_action(CAPABILITY=capability, MCP_AUDIT_VERSION=version)
    assert result.returncode == 0, result.stderr
    assert calls == [
        ["check", "--help"],
        [
            grammar,
            "--skip-connect",
            *(["--include-discovered"] if grammar == "check" else []),
            "--sarif",
            "mcp-audit.sarif",
        ],
    ]
    assert "exit-code=0\n" in outputs


def test_capability_probe_does_not_trust_requested_version(run_action: RunAction) -> None:
    _, calls, _ = run_action(CAPABILITY="old", MCP_AUDIT_VERSION="3.0.0")
    assert calls[1][0] == "scan"
    _, calls, _ = run_action(CAPABILITY="expanded", MCP_AUDIT_VERSION="2.11.0")
    assert calls[1][0] == "check"
    _, calls, _ = run_action(HELP_CODE="2")
    assert calls[1][0] == "scan"


@pytest.mark.parametrize("capability", ["old", "expanded"])
def test_structured_inputs_follow_grammar(run_action: RunAction, capability: str) -> None:
    result, calls, outputs = run_action(
        CAPABILITY=capability,
        CONFIG="fixture with spaces.json",
        CLIENTS="cursor,vscode",
        SARIF="report.sarif",
        JSON="report.json",
        POLICY="policy.yaml",
        SKIP_CONNECT="false",
    )
    assert result.returncode == 0, result.stderr
    assert calls[1] == (
        [
            "check",
            "--connect-all",
            "--client",
            "cursor",
            "--client",
            "vscode",
            "--config",
            "fixture with spaces.json",
            "--sarif",
            "report.sarif",
            "--output-json",
            "report.json",
            "--policy",
            "policy.yaml",
        ]
        if capability == "expanded"
        else [
            "scan",
            "--clients",
            "cursor,vscode",
            "--config",
            "fixture with spaces.json",
            "--config-only",
            "--sarif",
            "report.sarif",
            "--json",
            "report.json",
            "--policy",
            "policy.yaml",
        ]
    )
    assert "sarif-file=report.sarif\njson-file=report.json\n" in outputs


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (
            '--json "report with spaces.json" --clients cursor',
            ["--output-json", "report with spaces.json", "--client", "cursor"],
        ),
        ("--json=report.json --clients=vscode", ["--output-json", "report.json", "--client", "vscode"]),
        ("--json --inject-check", ["--json", "--inject-check"]),
        ("--json", ["--json"]),
        (
            '--output-json "report with spaces.json" --timeout 12 --inject-check',
            ["--output-json", "report with spaces.json", "--timeout", "12", "--inject-check"],
        ),
        (
            '--ignore-reason "--clients" --client cursor',
            ["--ignore-reason", "--clients", "--client", "cursor"],
        ),
        ("-- --clients cursor", ["--", "--clients", "cursor"]),
    ],
)
def test_check_args_translation_and_command_notice(
    run_action: RunAction, extra: str, expected: list[str]
) -> None:
    result, calls, _ = run_action(EXTRA_ARGS=extra)
    assert result.returncode == 0, result.stderr
    assert calls[1] == [
        "check",
        "--skip-connect",
        "--include-discovered",
        "--sarif",
        "mcp-audit.sarif",
        *expected,
    ]
    assert "args use check grammar; translated command:" in result.stderr
    notice = result.stderr.split("translated command: ", 1)[1].strip()
    assert shlex.split(notice) == ["mcp-audit", *calls[1]]


@pytest.mark.parametrize("extra", ["--clients cursor,vscode", "--clients=cursor,vscode", "--clients"])
def test_untranslatable_clients_fail_before_audit(run_action: RunAction, extra: str) -> None:
    result, calls, outputs = run_action(EXTRA_ARGS=extra)
    assert result.returncode == 0  # The existing upload-then-enforce step gates exit-code.
    assert calls == [["check", "--help"]]
    assert "--client NAME" in result.stderr
    assert "exit-code=2\n" in outputs


def test_legacy_args_are_unchanged_and_not_evaluated(run_action: RunAction) -> None:
    extra = '--json report.json --clients cursor,vscode --ignore-reason "$(exit 9) *.json"'
    result, calls, _ = run_action(CAPABILITY="old", EXTRA_ARGS=extra)
    assert result.returncode == 0, result.stderr
    assert calls[1] == ["scan", "--skip-connect", "--sarif", "mcp-audit.sarif", *shlex.split(extra)]
    assert "args use scan grammar; translated command:" in result.stderr


@pytest.mark.parametrize("extra", ['"unterminated', "--json="])
def test_bad_args_fail_before_audit(run_action: RunAction, extra: str) -> None:
    result, calls, outputs = run_action(EXTRA_ARGS=extra)
    assert result.returncode == 0
    assert calls == [["check", "--help"]]
    assert "exit-code=2\n" in outputs


def test_connection_selection_and_config_only_are_preserved(run_action: RunAction) -> None:
    _, calls, _ = run_action(SKIP_CONNECT="false", EXTRA_ARGS="--connect --server cursor:project:fixture")
    assert "--connect-all" not in calls[1]
    assert "--connect" in calls[1]
    _, calls, _ = run_action(EXTRA_ARGS="--connect-all")
    assert "--skip-connect" in calls[1] and "--connect-all" in calls[1]
    _, calls, _ = run_action(EXTRA_ARGS="--config fixture.json --config-only")
    assert "--config-only" in calls[1] and "--include-discovered" not in calls[1]
    _, calls, _ = run_action(EXTRA_ARGS="--ignore-reason=--config-only")
    assert "--include-discovered" in calls[1]
    _, calls, _ = run_action(EXTRA_ARGS='--ignore-reason "--config-only"')
    assert "--include-discovered" in calls[1]


def test_audit_failure_is_recorded_for_existing_gate(run_action: RunAction) -> None:
    result, _, outputs = run_action(SCAN_CODE="2", SARIF="", JSON="report.json")
    assert result.returncode == 0
    assert outputs == "exit-code=2\nsarif-file=\njson-file=report.json\n"


def test_hook_checks_synthetic_discovered_config_without_connections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"fixture": {"command": "never-start"}}}))

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static hook must not connect")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    hook = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())[0]
    command = shlex.split(hook["entry"])
    result = CliRunner().invoke(cli.main, [*command[1:], "--json", "--override-config", "/dev/null"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_discovered"] == 1
    assert report["coverage"]["inject_check"]["state"] == "not_run"
    assert report["coverage"]["metadata"]["reason"] == "connections disabled"


def test_translated_action_command_runs_against_synthetic_config(
    run_action: RunAction, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "fixture.json"
    config.write_text(json.dumps({"mcpServers": {"fixture": {"command": "never-start"}}}))
    output = tmp_path / "report with spaces.json"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    result, calls, _ = run_action(
        CONFIG=str(config),
        SARIF="",
        EXTRA_ARGS=f'--json "{output}" --inject-check --override-config /dev/null',
    )
    assert result.returncode == 0

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static Action must not connect")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    checked = CliRunner().invoke(cli.main, calls[1])
    assert checked.exit_code == 0, checked.output
    report = json.loads(output.read_text())
    assert report["servers_discovered"] == 1
    assert report["coverage"]["metadata"]["reason"] == "connections disabled"


@pytest.mark.parametrize("extra", ["--connect-all", "--connect --server cursor:project:fixture"])
def test_default_action_rejects_connections_before_discovery(
    run_action: RunAction, monkeypatch: pytest.MonkeyPatch, extra: str
) -> None:
    _, calls, _ = run_action(EXTRA_ARGS=extra)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("conflicting connection flags must fail before discovery")

    monkeypatch.setattr(check_cli, "review_sources", forbidden)
    checked = CliRunner().invoke(cli.main, calls[1])
    assert checked.exit_code == 2, checked.output
    assert "--skip-connect cannot be combined" in checked.output


def test_recorded_failure_is_enforced_by_action_gate() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    gate = next(step for step in action["runs"]["steps"] if step["name"] == "Enforce scan result")
    result = subprocess.run(
        ["bash", "-c", gate["run"]], env={**os.environ, "CODE": "2"}, capture_output=True, text=True
    )
    assert result.returncode == 2
