"""Startup, compatibility, and distribution contracts for the lazy CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from zipfile import ZipFile

import click
import pytest
from click.testing import CliRunner

from mcp_audit._command_registry import COMMANDS, LAB_COMMANDS, CommandSpec, LazyGroup, NamespaceSpec
from mcp_audit.cli import main

ROOT = Path(__file__).resolve().parents[1]
CORE_IMPORTS = {
    "mcp_audit",
    "mcp_audit.cli",
    "mcp_audit._command_registry",
    "mcp_audit.normalize",
    "mcp_audit.terminal_text",
}


@pytest.mark.parametrize("args", [None, ["--help"], ["--help-all"], ["lab", "--help"]])
def test_startup_and_registry_help_import_only_five_core_modules(args: list[str] | None) -> None:
    script = (
        "import json, sys; from mcp_audit.cli import main; "
        "from click.testing import CliRunner; "
        f"args = {args!r}; "
        "result = CliRunner().invoke(main, args) if args is not None else None; "
        "assert result is None or result.exit_code == 0, result.output; "
        "print(json.dumps(sorted(name for name in sys.modules "
        "if name == 'mcp_audit' or name.startswith('mcp_audit.'))))"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    modules = json.loads(result.stdout)
    assert len(modules) == 5
    assert set(modules) == CORE_IMPORTS


def test_name_completion_never_imports_command_implementations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_import(name: str) -> None:
        raise AssertionError(f"completion imported {name}")

    monkeypatch.setattr("mcp_audit._command_registry.import_module", forbidden_import)
    ctx = click.Context(main)
    assert {item.value for item in main.shell_complete(ctx, "")} >= set(COMMANDS)
    assert {item.value for item in main.shell_complete(ctx, "safeforge-")} == {
        "safeforge-preinstall",
        "safeforge-run",
    }
    lab = main.get_command(ctx, "lab")
    assert isinstance(lab, LazyGroup)
    assert {item.value for item in lab.shell_complete(click.Context(lab), "")} == set(LAB_COMMANDS)
    assert "--debug" in {item.value for item in main.shell_complete(ctx, "--")}


def test_help_all_enumerates_every_canonical_and_legacy_path() -> None:
    runner = CliRunner()
    ordinary = runner.invoke(main, ["--help"])
    exhaustive = runner.invoke(main, ["--help-all"])
    assert ordinary.exit_code == exhaustive.exit_code == 0
    ordinary_rows = {line.strip().split("  ")[0] for line in ordinary.output.splitlines()}
    all_rows = {line.strip().split("  ")[0] for line in exhaustive.output.splitlines()}
    for name, spec in COMMANDS.items():
        assert name in all_rows
        assert (name in ordinary_rows) is not spec.hidden
        if isinstance(spec, NamespaceSpec):
            for child_name, child in spec.children.items():
                path = f"{name} {child_name}"
                assert path in all_rows
                for leaf in child.subcommands:
                    assert f"{path} {leaf}" in all_rows
        else:
            for leaf in spec.subcommands:
                assert f"{name} {leaf}" in all_rows


@pytest.mark.parametrize("name,spec", list(COMMANDS.items()))
def test_every_registered_command_resolves_and_metadata_covers_subcommands(
    name: str,
    spec: CommandSpec | NamespaceSpec,
) -> None:
    command = main.get_command(click.Context(main), name)
    assert command is not None
    assert command.hidden is spec.hidden
    if isinstance(spec, NamespaceSpec):
        assert isinstance(command, LazyGroup)
        for child_name, child in spec.children.items():
            implementation = command.get_command(click.Context(command), child_name)
            assert implementation is not None
            if isinstance(implementation, click.Group):
                assert set(implementation.list_commands(click.Context(implementation))) == set(
                    child.subcommands
                )
    elif isinstance(command, click.Group):
        assert set(command.list_commands(click.Context(command))) == set(spec.subcommands)


LAB_CASES = [
    ("agent-ui", ["scan", "tests/fixtures/agent_ui/mcpui001-authority-positive.json"]),
    ("authorization-posture", ["schema", "report"]),
    ("cache-contract", ["scan", "tests/fixtures/cache_contract/benign-event-negative.json"]),
    ("enforcement-fixture", ["prepare"]),
    ("oauth-transcript", ["scan", "tests/fixtures/oauth_transcript/mcpoauth001-negative.json"]),
    ("result-parcel", ["analyze", "--builtin", "small-inline", "--format", "json"]),
    ("session-resume", ["run", "--all", "--format", "json"]),
    ("task-time-machine", ["run", "--builtin", "happy-path", "--json"]),
]


@pytest.mark.parametrize("name,args", LAB_CASES)
def test_lab_and_old_paths_keep_original_output_bytes(name: str, args: list[str]) -> None:
    spec = LAB_COMMANDS[name]
    implementation = getattr(import_module(spec.module), spec.attribute)
    runner = CliRunner()
    original = runner.invoke(implementation, args)
    legacy = runner.invoke(main, [name, *args])
    canonical = runner.invoke(main, ["lab", name, *args])
    assert original.exit_code == legacy.exit_code == canonical.exit_code
    assert original.stdout_bytes == legacy.stdout_bytes == canonical.stdout_bytes
    assert original.stderr_bytes == legacy.stderr_bytes == canonical.stderr_bytes
    if name != "enforcement-fixture":
        assert original.exit_code in {0, 1}, original.output
        assert original.stdout_bytes


@pytest.mark.parametrize(
    "legacy,canonical",
    [
        ("safeforge-preinstall", ["safeforge", "preinstall"]),
        ("safeforge-run", ["safeforge", "run"]),
        ("skillscan", ["skills", "scan"]),
        ("pin", ["baseline", "pin"]),
    ],
)
def test_side_product_aliases_share_callbacks_and_help(legacy: str, canonical: list[str]) -> None:
    ctx = click.Context(main)
    old = main.get_command(ctx, legacy)
    group = main.get_command(ctx, canonical[0])
    assert isinstance(group, LazyGroup)
    new = group.get_command(click.Context(group), canonical[1])
    assert old is not None and new is not None
    assert old.callback is new.callback
    runner = CliRunner()
    old_help = runner.invoke(main, [legacy, "--help"])
    new_help = runner.invoke(main, [*canonical, "--help"])
    assert old_help.exit_code == new_help.exit_code == 0
    # Usage intentionally names the spelling used; all option/help text stays identical.
    assert old_help.output.split("\n", 1)[1] == new_help.output.split("\n", 1)[1]
    assert old.hidden and not new.hidden


@pytest.mark.parametrize("family", ["preinstall", "run", "skills", "baseline"])
def test_side_product_aliases_keep_output_bytes(family: str, tmp_path: Path) -> None:
    if family in {"preinstall", "run"}:
        invalid = tmp_path / "invalid.json"
        invalid.write_text("[]", encoding="utf-8")
        args = [
            "--producer-schema",
            str(invalid),
            "--receipt",
            str(invalid),
            "--artifact-root",
            str(tmp_path),
            "--run-id",
            "synthetic-run",
            "--created-at",
            "2026-01-01T00:00:00Z",
            "--coordinator-revision",
            "synthetic",
        ]
        old = [f"safeforge-{family}", *args]
        new = ["safeforge", family, *args]
    elif family == "skills":
        skill = tmp_path / "skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\nname: synthetic\ndescription: Offline fixture\n---\nUse local fixtures.\n", encoding="utf-8"
        )
        old = ["skillscan", str(skill)]
        new = ["skills", "scan", str(skill)]
    else:
        args = ["--status", "--json", "--pin-file", str(tmp_path / "pins.yaml")]
        old = ["pin", *args]
        new = ["baseline", "pin", *args]
    runner = CliRunner()
    legacy = runner.invoke(main, old)
    canonical = runner.invoke(main, new)
    assert legacy.exit_code == canonical.exit_code == (2 if family in {"preinstall", "run"} else 0)
    assert legacy.stdout_bytes == canonical.stdout_bytes
    assert legacy.stderr_bytes == canonical.stderr_bytes
    assert legacy.stdout_bytes


def test_monitor_is_hidden_and_warns_before_legacy_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_audit import monitor

    calls: list[str] = []

    async def fixture_monitor(server_name: str, log_path: str | None) -> None:
        calls.append(server_name)

    monkeypatch.setattr(monitor, "_run_monitor", fixture_monitor)
    result = CliRunner().invoke(main, ["monitor", "synthetic-peer"])
    assert result.exit_code == 0, result.output
    assert calls == ["synthetic-peer"]
    assert "DeprecationWarning" in result.stderr
    assert "3.0" in result.stderr


@pytest.mark.parametrize("module", ["oauth_transcript_cli", "authorization_posture_cli"])
def test_shared_artifact_writer_does_not_import_agent_ui(module: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys; import mcp_audit.{module}; "
            "assert not any(name.startswith('mcp_audit.agent_ui') for name in sys.modules)",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_wheel_contains_listed_runtime_files_and_no_postgres_research(tmp_path: Path) -> None:
    build = subprocess.run(
        ["uv", "build", "--wheel", "--offline", "--out-dir", str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    with ZipFile(wheels[0]) as wheel:
        files = {name for name in wheel.namelist() if not name.endswith("/")}
    package_files = {name for name in files if name.startswith("mcp_audit/")}
    assert package_files == set(EXPECTED_WHEEL_FILES.split())
    assert not any("proofos_postgres" in name or name.startswith("research/") for name in files)
    assert all(name.startswith(("mcp_audit/", "mcp_audits-")) for name in files)


EXPECTED_WHEEL_FILES = """
mcp_audit/__init__.py
mcp_audit/_artifacts.py
mcp_audit/_build_provenance.json
mcp_audit/_command_registry.py
mcp_audit/_core_cli.py
mcp_audit/agent_text.py
mcp_audit/agent_ui_cli.py
mcp_audit/agent_ui_models.py
mcp_audit/agent_ui_scanner.py
mcp_audit/analyzer.py
mcp_audit/api.py
mcp_audit/artifact_paths.py
mcp_audit/authorization_posture_cli.py
mcp_audit/authorization_posture_models.py
mcp_audit/authorization_posture_scanner.py
mcp_audit/cache_contract_cli.py
mcp_audit/cache_contract_models.py
mcp_audit/cache_contract_scanner.py
mcp_audit/canonical.py
mcp_audit/check_cli.py
mcp_audit/checkup.py
mcp_audit/cli.py
mcp_audit/confighealth.py
mcp_audit/connector.py
mcp_audit/coverage.py
mcp_audit/discovery/__init__.py
mcp_audit/discovery/_config.py
mcp_audit/discovery/_entry.py
mcp_audit/discovery/base.py
mcp_audit/discovery/claude_code.py
mcp_audit/discovery/claude_desktop.py
mcp_audit/discovery/cursor.py
mcp_audit/discovery/vscode.py
mcp_audit/discovery/windsurf.py
mcp_audit/egress.py
mcp_audit/enforcement_cli.py
mcp_audit/engine.py
mcp_audit/escalation.py
mcp_audit/evidence_enforcement.py
mcp_audit/finding_display.py
mcp_audit/fixture_gateway.py
mcp_audit/fixtures/demo-mcp-config.json
mcp_audit/htmlreport.py
mcp_audit/injection.py
mcp_audit/integrity.py
mcp_audit/llm_analyzer.py
mcp_audit/models.py
mcp_audit/monitor.py
mcp_audit/normalize.py
mcp_audit/oauth_transcript_cli.py
mcp_audit/oauth_transcript_models.py
mcp_audit/oauth_transcript_sarif.py
mcp_audit/oauth_transcript_scanner.py
mcp_audit/overrides.py
mcp_audit/pin_cli.py
mcp_audit/pinning.py
mcp_audit/pkgverify.py
mcp_audit/policy.py
mcp_audit/proof_capsule.py
mcp_audit/proof_cli.py
mcp_audit/proof_models.py
mcp_audit/proof_observer.py
mcp_audit/proof_trust.py
mcp_audit/protocol.py
mcp_audit/provenance.py
mcp_audit/redaction.py
mcp_audit/report.py
mcp_audit/result_parcel_cli.py
mcp_audit/result_parcel_models.py
mcp_audit/result_parcel_scanner.py
mcp_audit/review_discovery.py
mcp_audit/rules/__init__.py
mcp_audit/rules/patterns.py
mcp_audit/rules/result_injection.py
mcp_audit/rules/weights.py
mcp_audit/safeforge.py
mcp_audit/safeforge_cli.py
mcp_audit/safeforge_consumer.py
mcp_audit/safeforge_contract_linter.py
mcp_audit/safeforge_coordinator.py
mcp_audit/safeforge_runtime.py
mcp_audit/sarif.py
mcp_audit/scan_cli.py
mcp_audit/schema_rules.py
mcp_audit/scorer.py
mcp_audit/server.py
mcp_audit/session_resume_cli.py
mcp_audit/session_resume_lab.py
mcp_audit/session_resume_models.py
mcp_audit/session_resume_scenarios_v1.json
mcp_audit/shadowing.py
mcp_audit/skillscan.py
mcp_audit/skillscan_cli.py
mcp_audit/skillscan_models.py
mcp_audit/ssrf.py
mcp_audit/stdio_transport.py
mcp_audit/surface_limits.py
mcp_audit/suppressions.py
mcp_audit/task_time_machine.py
mcp_audit/task_time_machine_cli.py
mcp_audit/task_time_machine_models.py
mcp_audit/taxonomy.py
mcp_audit/terminal_summary.py
mcp_audit/terminal_text.py
mcp_audit/text_limits.py
mcp_audit/trifecta.py
mcp_audit/ux_summary.py
mcp_audit/watcher.py
"""
