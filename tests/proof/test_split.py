"""Acceptance checks for Proof's independent distribution boundary."""

from __future__ import annotations

import ast
import importlib.metadata
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner
from proof_before_action import proof_capsule, proof_cli

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "distributions/proof/src/proof_before_action"
MODULES = {"proof_capsule", "proof_cli", "proof_models", "proof_observer", "proof_trust"}


def test_proof_modules_and_console_script_belong_only_to_proof() -> None:
    core = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    proof = tomllib.loads((ROOT / "distributions/proof/pyproject.toml").read_text())["project"]
    assert core["scripts"] == {
        "mcp-audit": "mcp_audit.cli:main",
        "mcp-audits": "mcp_audit.cli:main",
    }
    assert proof["scripts"] == {"proof-before-action": "proof_before_action.proof_cli:main"}
    assert {path.stem for path in PACKAGE.glob("proof_*.py")} == MODULES
    assert not list((ROOT / "src/mcp_audit").glob("proof_*.py"))


def test_proof_import_graph_excludes_core() -> None:
    violations: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)):
                continue
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                targets = [node.module or ""]
            elif (
                isinstance(node, ast.Call)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"import_module", "__import__"}
                    or isinstance(node.func, ast.Attribute)
                    and node.func.attr == "import_module"
                )
            ):
                targets = [node.args[0].value]
            for target in targets:
                if target == "mcp_audit" or target.startswith("mcp_audit."):
                    violations.append(f"{path.name}:{node.lineno} -> {target}")
    assert not violations, "Proof imports core:\n" + "\n".join(violations)


def test_proof_imports_and_cli_work_when_core_is_unavailable() -> None:
    code = """
import importlib
import importlib.abc
import sys
from click.testing import CliRunner

class NoCore(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'mcp_audit' or fullname.startswith('mcp_audit.'):
            raise AssertionError('Proof tried to import core: ' + fullname)

sys.meta_path.insert(0, NoCore())
for module in ('proof_capsule', 'proof_cli', 'proof_models', 'proof_observer', 'proof_trust'):
    importlib.import_module('proof_before_action.' + module)
from proof_before_action.proof_cli import main
for args in (['--help'], ['--version'], ['schema', 'declaration']):
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.exception
assert not any(name == 'mcp_audit' or name.startswith('mcp_audit.') for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_proof_version_reads_its_own_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def version(name: str) -> str:
        assert name == "mcp-audits-proof"
        return "9.8.7"

    monkeypatch.setattr(importlib.metadata, "version", version)
    namespace = runpy.run_path(str(PACKAGE / "__init__.py"))
    assert namespace["__version__"] == "9.8.7"


def test_proof_cli_has_its_own_current_install_notice_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proof_cli, "__version__", "9.8.7")
    result = CliRunner().invoke(proof_cli.main, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == "proof-before-action, version 9.8.7\n"
    assert result.stderr == proof_cli.PROOF_INSTALL_NOTICE + "\n"
    assert "uv tool install mcp-audits-proof" in result.stderr
    assert "a uv tool extra does not expose its scripts" in result.stderr
    assert "In 3.0" not in result.stderr


def test_split_checkout_producer_provenance_is_present() -> None:
    expected = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    commit, dirty, source = proof_capsule._producer_state()
    assert commit == expected
    assert isinstance(dirty, bool)
    assert source == "source-checkout"


def test_package_version_falls_back_when_distribution_metadata_is_missing() -> None:
    import importlib

    import proof_before_action

    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(importlib.metadata, "version", missing)
            assert importlib.reload(proof_before_action).__version__ == "0.0.0"
    finally:
        importlib.reload(proof_before_action)
    assert proof_before_action.__version__ == importlib.metadata.version("mcp-audits-proof")
