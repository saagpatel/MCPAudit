"""Tests for the CI distribution artifacts: the composite GitHub Action,
the pre-commit hook definition, and the self-audit workflow.

These guard the adoption surface (one-line Action + pre-commit) against
regressions and enforce two invariants that matter for a security tool:

  - The Action must run config-only by default and still upload SARIF.
  - No `run:` step may interpolate `${{ inputs.* }}` directly into the shell
    (command-injection hygiene); inputs flow through `env:` instead.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ACTION_PATH = Path("action.yml")
PRECOMMIT_PATH = Path(".pre-commit-hooks.yaml")
SELF_AUDIT_PATH = Path(".github/workflows/self-audit.yml")


def _public_action_version() -> str:
    data = json.loads(Path("docs/release-state.json").read_text(encoding="utf-8"))
    version = data["published_version"]
    assert isinstance(version, str)
    return version


def _action() -> dict[str, Any]:
    parsed = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


class TestCompositeAction:
    def test_is_composite_action(self) -> None:
        runs = _action()["runs"]
        assert runs["using"] == "composite"
        assert isinstance(runs["steps"], list) and runs["steps"]

    def test_installs_published_package_and_runs_adapter(self) -> None:
        text = ACTION_PATH.read_text(encoding="utf-8")
        assert "mcp-audits" in text
        assert 'python "${MCP_AUDIT_ACTION_PATH}/scripts/run_action.py"' in text

    def test_defaults_to_config_only(self) -> None:
        assert _action()["inputs"]["skip-connect"]["default"] == "true"

    def test_uploads_sarif_by_default(self) -> None:
        action = _action()
        assert action["inputs"]["upload-sarif"]["default"] == "true"
        assert action["inputs"]["sarif-category"]["default"] == "mcp-audit"
        steps_text = yaml.dump(action["runs"]["steps"])
        assert "github/codeql-action/upload-sarif" in steps_text
        assert "category" in steps_text

    def test_exposes_outputs(self) -> None:
        outputs = _action()["outputs"]
        assert {"sarif-file", "json-file", "exit-code"} <= set(outputs)

    def test_no_input_interpolated_into_run_blocks(self) -> None:
        # Command-injection hygiene: inputs must be passed via env:, never
        # interpolated straight into a shell `run:` block.
        for step in _action()["runs"]["steps"]:
            run_block = step.get("run")
            if run_block:
                assert "${{ inputs." not in run_block, (
                    f"step {step.get('name')!r} interpolates an input into run:"
                )

    def test_scan_step_passes_inputs_through_env(self) -> None:
        scan_step = next(step for step in _action()["runs"]["steps"] if step.get("id") == "scan")
        assert "SKIP_CONNECT" in scan_step["env"]


class TestPreCommitHook:
    def test_defines_mcp_audit_hook(self) -> None:
        hooks = yaml.safe_load(PRECOMMIT_PATH.read_text(encoding="utf-8"))
        assert isinstance(hooks, list)
        hook = next(h for h in hooks if h["id"] == "mcp-audit")
        assert hook["language"] == "python"
        assert hook["pass_filenames"] is False
        assert hook["entry"] == "mcp-audit check --include-discovered --inject-check"

    def test_triggers_on_repo_local_configs(self) -> None:
        hooks = yaml.safe_load(PRECOMMIT_PATH.read_text(encoding="utf-8"))
        hook = next(h for h in hooks if h["id"] == "mcp-audit")
        pattern = re.compile(hook["files"])
        assert pattern.search(".mcp.json")
        assert pattern.search("sub/dir/.mcp.json")
        assert pattern.search(".vscode/mcp.json")
        # Should not fire on unrelated JSON.
        assert not pattern.search("package.json")

    def test_rev_in_docs_matches_public_release(self) -> None:
        # Candidate metadata may move ahead, but examples must name an existing public tag.
        version_tag = f"v{_public_action_version()}"
        adoption = Path("docs/ADOPTION-GUIDE.md").read_text(encoding="utf-8")
        assert f"rev: {version_tag}" in adoption


class TestSelfAuditWorkflow:
    def test_dogfoods_local_action(self) -> None:
        workflow = yaml.safe_load(SELF_AUDIT_PATH.read_text(encoding="utf-8"))
        job = workflow["jobs"]["self-audit"]
        steps_text = yaml.dump(job["steps"])
        assert "uses: ./" in SELF_AUDIT_PATH.read_text(encoding="utf-8") or "./" in steps_text
        assert job["permissions"]["security-events"] == "write"

    def test_builds_only_the_core_distribution(self) -> None:
        text = SELF_AUDIT_PATH.read_text(encoding="utf-8")
        assert "uv build --package mcp-audits --wheel --out-dir dist" in text


def _build_wheel(package: str, output: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--package", package, "--wheel", "--out-dir", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _install_wheel(
    wheel: Path, prefix: Path, *, forbidden_modules: tuple[str, ...]
) -> tuple[dict[str, str], Path]:
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            sys.executable,
            "--prefix",
            str(prefix),
            "--no-deps",
            str(wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    env = os.environ.copy()
    site_packages = (
        prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    )
    site_packages.mkdir(parents=True, exist_ok=True)
    blocked = repr(forbidden_modules)
    (site_packages / "sitecustomize.py").write_text(
        "import importlib.abc, sys\n"
        f"blocked = {blocked}\n"
        "class DistributionBoundary(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        "        if any(fullname == name or fullname.startswith(name + '.') for name in blocked):\n"
        "            raise AssertionError('unexpected distribution import: ' + fullname)\n"
        "sys.meta_path.insert(0, DistributionBoundary())\n",
        encoding="utf-8",
    )
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(site_packages), env.get("PYTHONPATH", "")]))
    return env, prefix / "bin"


def test_core_only_install_has_core_commands_and_no_proof_script(tmp_path: Path) -> None:
    wheel = _build_wheel("mcp-audits", tmp_path / "wheel")
    env, scripts = _install_wheel(
        wheel, tmp_path / "core", forbidden_modules=("mcp_audit_labs", "proof_before_action")
    )
    fixture = Path("examples/sandbox/fixtures/synthetic-mcp-config.json").resolve()
    check = subprocess.run(
        [
            str(scripts / "mcp-audit"),
            "check",
            "--config",
            str(fixture),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
        ],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stderr
    for command in ("lab", "safeforge"):
        result = subprocess.run(
            [str(scripts / "mcp-audit"), command],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "uv tool install 'mcp-audits[labs]'" in result.stderr
    assert not (scripts / "proof-before-action").exists()


def test_proof_only_install_runs_without_core_distribution(tmp_path: Path) -> None:
    wheel = _build_wheel("mcp-audits-proof", tmp_path / "wheel")
    env, scripts = _install_wheel(wheel, tmp_path / "proof", forbidden_modules=("mcp_audit",))
    result = subprocess.run(
        [str(scripts / "proof-before-action"), "--version"],
        env={**env, "PYTHONPATH": env["PYTHONPATH"]},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "proof-before-action, version" in result.stdout
