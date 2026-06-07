"""Tests for the CI distribution artifacts: the composite GitHub Action,
the pre-commit hook definition, and the self-audit workflow.

These guard the adoption surface (one-line Action + pre-commit) against
regressions and enforce two invariants that matter for a security tool:

  - The Action must run config-only by default and still upload SARIF.
  - No `run:` step may interpolate `${{ inputs.* }}` directly into the shell
    (command-injection hygiene); inputs flow through `env:` instead.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

ACTION_PATH = Path("action.yml")
PRECOMMIT_PATH = Path(".pre-commit-hooks.yaml")
SELF_AUDIT_PATH = Path(".github/workflows/self-audit.yml")


def _package_version() -> str:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    version = data["project"]["version"]
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

    def test_installs_published_package_and_runs_scan(self) -> None:
        text = ACTION_PATH.read_text(encoding="utf-8")
        assert "mcp-audit" in text
        assert "mcp-audit scan" in text

    def test_defaults_to_config_only(self) -> None:
        assert _action()["inputs"]["skip-connect"]["default"] == "true"

    def test_uploads_sarif_by_default(self) -> None:
        action = _action()
        assert action["inputs"]["upload-sarif"]["default"] == "true"
        steps_text = yaml.dump(action["runs"]["steps"])
        assert "github/codeql-action/upload-sarif" in steps_text

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
        assert "--skip-connect" in hook["entry"]

    def test_triggers_on_repo_local_configs(self) -> None:
        hooks = yaml.safe_load(PRECOMMIT_PATH.read_text(encoding="utf-8"))
        hook = next(h for h in hooks if h["id"] == "mcp-audit")
        pattern = re.compile(hook["files"])
        assert pattern.search(".mcp.json")
        assert pattern.search("sub/dir/.mcp.json")
        assert pattern.search(".vscode/mcp.json")
        # Should not fire on unrelated JSON.
        assert not pattern.search("package.json")

    def test_rev_in_docs_matches_package_version(self) -> None:
        # The pre-commit usage example pins `rev: v<version>`; keep it in sync.
        version_tag = f"v{_package_version()}"
        adoption = Path("docs/ADOPTION-GUIDE.md").read_text(encoding="utf-8")
        assert f"rev: {version_tag}" in adoption


class TestSelfAuditWorkflow:
    def test_dogfoods_local_action(self) -> None:
        workflow = yaml.safe_load(SELF_AUDIT_PATH.read_text(encoding="utf-8"))
        job = workflow["jobs"]["self-audit"]
        steps_text = yaml.dump(job["steps"])
        assert "uses: ./" in SELF_AUDIT_PATH.read_text(encoding="utf-8") or "./" in steps_text
        assert job["permissions"]["security-events"] == "write"
