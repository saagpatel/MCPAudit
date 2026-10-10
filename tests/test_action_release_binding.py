"""Release binding checks for the composite Action and its self-audit."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def action_install_script() -> str:
    action: dict[str, Any] = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = action["runs"]["steps"]
    install_step = next(step for step in steps if step["name"] == "Install MCPAudit")
    script = install_step["run"]
    assert isinstance(script, str)
    return script


@pytest.fixture
def install_runner(tmp_path: Path) -> tuple[Path, Path]:
    """Create a python shim that records pip arguments and delegates other calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_path = tmp_path / "pip-argv.json"
    shim = bin_dir / "python"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['-m', 'pip']:\n"
        "    pathlib.Path(os.environ['PIP_ARGV_LOG']).write_text(json.dumps(args[2:]))\n"
        "    raise SystemExit(0)\n"
        "os.execv(os.environ['REAL_PYTHON'], [os.environ['REAL_PYTHON'], *args])\n"
    )
    shim.chmod(0o755)
    return shim, log_path


def run_install(
    script: str,
    action_path: Path,
    shim: Path,
    log_path: Path,
    *,
    version: str = "",
    wheel: str = "",
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "PATH": f"{shim.parent}:{os.environ['PATH']}",
        "REAL_PYTHON": shutil.which("python3") or "python3",
        "PIP_ARGV_LOG": str(log_path),
        "MCP_AUDIT_VERSION": version,
        "MCP_AUDIT_WHEEL": wheel,
        "MCP_AUDIT_ACTION_PATH": str(action_path),
    }
    return subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)


def test_empty_version_installs_action_pyproject_version(
    action_install_script: str, install_runner: tuple[Path, Path], tmp_path: Path
) -> None:
    shim, log_path = install_runner
    action_path = tmp_path / "action"
    action_path.mkdir()
    (action_path / "pyproject.toml").write_text('[project]\nname = "mcp-audits"\nversion = "8.1.3"\n')

    result = run_install(action_install_script, action_path, shim, log_path)

    assert result.returncode == 0, result.stderr
    assert json.loads(log_path.read_text()) == ["install", "--upgrade", "mcp-audits==8.1.3"]


def test_explicit_version_remains_an_exact_package_pin(
    action_install_script: str, install_runner: tuple[Path, Path], tmp_path: Path
) -> None:
    shim, log_path = install_runner

    result = run_install(action_install_script, tmp_path, shim, log_path, version="3.4.5")

    assert result.returncode == 0, result.stderr
    assert json.loads(log_path.read_text()) == ["install", "--upgrade", "mcp-audits==3.4.5"]

    wildcard = run_install(action_install_script, tmp_path, shim, log_path, version="3.4.*")
    assert wildcard.returncode != 0
    assert "exact semantic version" in wildcard.stdout


def test_local_wheel_is_installed_and_cannot_be_combined_with_version(
    action_install_script: str, install_runner: tuple[Path, Path], tmp_path: Path
) -> None:
    shim, log_path = install_runner
    wheel_path = tmp_path / "dist" / "mcp_audits-8.1.3-py3-none-any.whl"
    wheel_path.parent.mkdir()
    wheel_path.touch()
    wheel = str(wheel_path)

    result = run_install(action_install_script, tmp_path, shim, log_path, wheel=wheel)

    assert result.returncode == 0, result.stderr
    assert json.loads(log_path.read_text()) == ["install", "--upgrade", wheel]

    conflict = run_install(action_install_script, tmp_path, shim, log_path, wheel=wheel, version="8.1.3")
    assert conflict.returncode != 0
    assert "either wheel or version" in conflict.stdout

    remote = run_install(
        action_install_script, tmp_path, shim, log_path, wheel="https://example.invalid/package.whl"
    )
    assert remote.returncode != 0
    assert "existing regular .whl file" in remote.stdout


def test_self_audit_builds_and_installs_the_local_versioned_wheel() -> None:
    workflow: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows/self-audit.yml").read_text())
    steps = workflow["jobs"]["self-audit"]["steps"]
    build = next(step for step in steps if step.get("id") == "build")
    audit = next(step for step in steps if step.get("uses") == "./")

    assert "uv build --wheel --out-dir dist" in build["run"]
    assert "pyproject.toml" in build["run"]
    assert "mcp_audits-{version}-*.whl" in build["run"]
    setup_uv = next(step for step in steps if "astral-sh/setup-uv@" in step.get("uses", ""))
    assert setup_uv["with"]["python-version"] == "3.11"
    assert setup_uv["with"]["enable-cache"] is False
    assert audit["with"]["wheel"] == "${{ steps.build.outputs.wheel }}"
    assert steps.index(build) < steps.index(audit)
