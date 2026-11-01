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

from mcp_audit._command_registry import (
    COMMANDS,
    LAB_COMMANDS,
    LAB_INSTALL_NOTICE,
    CommandSpec,
    LazyGroup,
    NamespaceSpec,
)
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
        "assert not any(name.startswith('mcp_audit_labs') for name in sys.modules); "
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
    assert {item.value for item in main.shell_complete(ctx, "safeforge-")} == set()
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
    assert "Compatibility aliases" not in ordinary.output
    assert "Compatibility aliases" not in exhaustive.output
    assert "--help-all" in ordinary.output


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
def test_lab_paths_keep_original_output_bytes(name: str, args: list[str]) -> None:
    spec = LAB_COMMANDS[name]
    implementation = getattr(import_module(spec.module), spec.attribute)
    runner = CliRunner()
    original = runner.invoke(implementation, args)
    canonical = runner.invoke(main, ["lab", name, *args])
    assert original.exit_code == canonical.exit_code
    assert original.stdout_bytes == canonical.stdout_bytes
    assert original.stderr_bytes == canonical.stderr_bytes
    if name != "enforcement-fixture":
        assert original.exit_code in {0, 1}, original.output
        assert original.stdout_bytes


def test_pin_alias_shares_callback_and_help() -> None:
    ctx = click.Context(main)
    alias = main.get_command(ctx, "pin")
    group = main.get_command(ctx, "baseline")
    assert isinstance(group, LazyGroup)
    canonical = group.get_command(click.Context(group), "pin")
    assert alias is not None and canonical is not None
    assert alias.callback is canonical.callback
    runner = CliRunner()
    alias_help = runner.invoke(main, ["pin", "--help"])
    canonical_help = runner.invoke(main, ["baseline", "pin", "--help"])
    assert alias_help.exit_code == canonical_help.exit_code == 0
    # Usage intentionally names the spelling used; all option/help text stays identical.
    assert alias_help.stdout.split("\n", 1)[1] == canonical_help.stdout.split("\n", 1)[1]
    assert not alias.hidden and not canonical.hidden


def test_monitor_command_and_module_are_removed() -> None:
    import importlib.util

    result = CliRunner().invoke(main, ["monitor", "synthetic-peer"])

    assert result.exit_code == 2
    assert "No such command 'monitor'" in result.output
    assert "monitor" not in COMMANDS
    assert importlib.util.find_spec("mcp_audit.monitor") is None


REMOVED_ALIASES = [*LAB_COMMANDS, "safeforge-preinstall", "safeforge-run", "skillscan"]


@pytest.mark.parametrize("name", REMOVED_ALIASES)
def test_removed_aliases_are_unknown_commands(name: str) -> None:
    result = CliRunner().invoke(main, [name, "--help"])
    assert result.exit_code == 2
    assert f"No such command '{name}'" in result.stderr
    assert "removed in 3.0" not in result.stderr
    assert name not in COMMANDS


def test_pin_is_a_visible_alias_for_baseline_pin() -> None:
    alias = COMMANDS["pin"]
    baseline = COMMANDS["baseline"]
    assert isinstance(alias, CommandSpec)
    assert isinstance(baseline, NamespaceSpec)
    canonical = baseline.children["pin"]
    assert isinstance(canonical, CommandSpec)
    assert not alias.hidden
    assert (alias.module, alias.attribute) == (canonical.module, canonical.attribute)
    help_text = CliRunner().invoke(main, ["--help"]).stdout
    assert "pin" in help_text
    assert "alias for baseline pin" in " ".join(help_text.split())


@pytest.mark.parametrize("family", ["preinstall", "run", "skills"])
def test_side_product_namespaced_paths_emit_output(
    family: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    if family in {"preinstall", "run"}:
        invalid = tmp_path / "invalid.json"
        invalid.write_text("[]", encoding="utf-8")
        args = [
            "safeforge",
            family,
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
        expected_exit = 2
    else:
        skill = tmp_path / "skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\nname: synthetic\ndescription: Offline fixture\n---\nUse local fixtures.\n", encoding="utf-8"
        )
        args = ["skills", "scan", str(skill)]
        expected_exit = 0
    result = CliRunner().invoke(main, args)
    assert result.exit_code == expected_exit, result.output
    assert result.stdout_bytes
    assert b"removed in 3.0" not in result.stderr_bytes


def test_pin_alias_keeps_baseline_pin_output_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    args = ["--status", "--json", "--pin-file", str(tmp_path / "pins.yaml")]
    runner = CliRunner()
    alias = runner.invoke(main, ["pin", *args])
    canonical = runner.invoke(main, ["baseline", "pin", *args])
    assert alias.exit_code == canonical.exit_code == 0
    assert alias.stdout_bytes
    assert alias.stdout_bytes == canonical.stdout_bytes
    assert alias.stderr_bytes == canonical.stderr_bytes


def test_lab_help_shows_future_installs_without_importing_labs(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_import(name: str) -> None:
        raise AssertionError(f"help imported {name}")

    monkeypatch.setattr("mcp_audit._command_registry.import_module", forbidden_import)
    result = CliRunner().invoke(main, ["lab", "--help"])
    assert result.exit_code == 0, result.output
    help_text = " ".join(result.stdout.split())
    assert "In 3.0" in help_text
    assert "uv tool install 'mcp-audits[labs]'" in result.stdout
    assert "uv tool install mcp-audits-proof" in result.stdout
    assert "a uv tool extra does not expose its scripts" in help_text
    assert result.stderr == ""


GUARDED_PATHS = [
    *[["lab", name, "--help"] for name in LAB_COMMANDS],
    ["safeforge", "preinstall", "--help"],
    ["safeforge", "run", "--help"],
    ["lab", "--conformance-probe", "--url", "http://127.0.0.1:1/mcp"],
]


@pytest.mark.parametrize("args", GUARDED_PATHS)
def test_live_dispatch_without_labs_preserves_the_212_install_notice(args: list[str]) -> None:
    script = """
import importlib.abc
import sys

class MissingLabs(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'mcp_audit_labs' or fullname.startswith('mcp_audit_labs.'):
            raise ModuleNotFoundError('synthetic missing distribution', name=fullname)

sys.meta_path.insert(0, MissingLabs())
from click.testing import CliRunner
from mcp_audit.cli import main
result = CliRunner().invoke(main, ARGS)
assert result.exit_code == 2, (result.exit_code, result.output)
assert result.stdout == '', result.stdout
assert (
    "Optional distribution missing. In 3.0, install labs with: "
    "uv tool install 'mcp-audits[labs]'. "
) in result.stderr
assert (
    'For proof-before-action on PATH, install Proof directly with: '
    'uv tool install mcp-audits-proof (a uv tool extra does not expose its scripts).'
) in result.stderr
""".replace("ARGS", repr(args))
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("args", GUARDED_PATHS)
@pytest.mark.parametrize(
    "missing",
    [
        "mcp_audit_labs",
        "mcp_audit_labs.agent_ui_cli",
        # Version skew: labs installed but missing a submodule core expects.
        "mcp_audit_labs.missing_submodule",
    ],
)
def test_missing_labs_exit_two_with_installs(
    args: list[str], missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing_import(name: str) -> None:
        raise ModuleNotFoundError("synthetic missing distribution", name=missing)

    monkeypatch.setattr("mcp_audit._command_registry.import_module", missing_import)
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    assert "Optional distribution missing" in result.stderr
    assert LAB_INSTALL_NOTICE in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("missing", ["proof_before_action", "proof_before_action.cli"])
def test_future_proof_distribution_guard(missing: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_import(name: str) -> None:
        raise ModuleNotFoundError("synthetic missing distribution", name=missing)

    monkeypatch.setattr("mcp_audit._command_registry.import_module", missing_import)
    future_proof = LazyGroup(
        registry={"proof": CommandSpec("proof_before_action.cli", "main", "Synthetic future entry.")}
    )
    result = CliRunner().invoke(future_proof, ["proof", "--help"])
    assert result.exit_code == 2, result.output
    assert "uv tool install mcp-audits-proof" in result.stderr
    assert "a uv tool extra does not expose its scripts" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("args", GUARDED_PATHS)
@pytest.mark.parametrize(
    "error",
    [
        *(
            ImportError("synthetic implementation defect", name=missing)
            for missing in (
                None,
                "anyio",
                "mcp_audit",
                "mcp_audit_labs_extra",
                "proof_before_action_extra",
                "mcp_audit_labs",
                "proof_before_action",
            )
        ),
        ImportError(
            "cannot import name 'x' from 'mcp_audit_labs.lab_primitives'",
            name="mcp_audit_labs.lab_primitives",
        ),
        ImportError(
            "cannot import name 'x' from partially initialized module 'mcp_audit_labs.agent_ui_cli' "
            "(most likely due to a circular import)",
            name="mcp_audit_labs.agent_ui_cli",
        ),
        ModuleNotFoundError("synthetic missing dependency", name="anyio"),
        ModuleNotFoundError("synthetic missing dependency", name="mcp_audit_labs_extra"),
    ],
    ids=repr,
)
def test_unrelated_import_errors_propagate(
    args: list[str], error: ImportError, monkeypatch: pytest.MonkeyPatch
) -> None:

    def broken_import(name: str) -> None:
        raise error

    monkeypatch.setattr("mcp_audit._command_registry.import_module", broken_import)
    result = CliRunner().invoke(main, args)
    assert result.exception is error
    assert "Optional distribution missing" not in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("module", ["oauth_transcript_cli", "authorization_posture_cli"])
def test_shared_artifact_writer_does_not_import_agent_ui(module: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys; import mcp_audit_labs.{module}; "
            "assert not any(name.startswith('mcp_audit_labs.agent_ui') for name in sys.modules)",
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
mcp_audit/_build_provenance.json
mcp_audit/_command_registry.py
mcp_audit/_core_cli.py
mcp_audit/agent_text.py
mcp_audit/analysis_budget.py
mcp_audit/analyzer.py
mcp_audit/api.py
mcp_audit/artifact_paths.py
mcp_audit/canonical.py
mcp_audit/check_cli.py
mcp_audit/checkup.py
mcp_audit/cli.py
mcp_audit/client_filter.py
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
mcp_audit/engine.py
mcp_audit/escalation.py
mcp_audit/finding_display.py
mcp_audit/fixtures/demo-mcp-config.json
mcp_audit/fix_cli.py
mcp_audit/fleet_workers.py
mcp_audit/htmlreport.py
mcp_audit/http_transport.py
mcp_audit/injection.py
mcp_audit/integrity.py
mcp_audit/llm_analyzer.py
mcp_audit/models.py
mcp_audit/normalize.py
mcp_audit/oauth_urls.py
mcp_audit/otel.py
mcp_audit/overrides.py
mcp_audit/pin_cli.py
mcp_audit/pin_signing.py
mcp_audit/pinning.py
mcp_audit/pkgverify.py
mcp_audit/policy.py
mcp_audit/probe.py
mcp_audit/proof_capsule.py
mcp_audit/proof_cli.py
mcp_audit/proof_models.py
mcp_audit/proof_observer.py
mcp_audit/proof_trust.py
mcp_audit/protocol.py
mcp_audit/provenance.py
mcp_audit/redaction.py
mcp_audit/report.py
mcp_audit/review_discovery.py
mcp_audit/rules/__init__.py
mcp_audit/rules/patterns.py
mcp_audit/rules/result_injection.py
mcp_audit/rules/weights.py
mcp_audit/sarif.py
mcp_audit/scan_cli.py
mcp_audit/scan_translation.py
mcp_audit/schema_rules.py
mcp_audit/scorer.py
mcp_audit/server.py
mcp_audit/shadowing.py
mcp_audit/shadow_cli.py
mcp_audit/skillscan.py
mcp_audit/skillscan_cli.py
mcp_audit/skillscan_models.py
mcp_audit/ssrf.py
mcp_audit/stdio_transport.py
mcp_audit/surface_limits.py
mcp_audit/suppressions.py
mcp_audit/taxonomy.py
mcp_audit/terminal_summary.py
mcp_audit/terminal_text.py
mcp_audit/text_limits.py
mcp_audit/trifecta.py
mcp_audit/ux_summary.py
mcp_audit/watcher.py
"""
