"""Pin the CI job that proves the core-only and Proof-only install shapes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_audit._command_registry import LAB_INSTALL_NOTICE

CI_PATH = Path(".github/workflows/ci.yml")
PACKAGES = ("mcp-audits", "mcp-audits-labs", "mcp-audits-proof")
LAB_NOTICE = "uv tool install 'mcp-audits[labs]'"


def _jobs() -> dict[str, Any]:
    workflow = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _steps(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {step["name"]: step for step in job["steps"] if "name" in step}


def test_install_shape_job_uses_pinned_actions_and_read_only_permissions() -> None:
    jobs = _jobs()
    job = jobs["install-shape"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["permissions"] == {"contents": "read"}
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    test_uses = {
        step["uses"].split("@", 1)[0]: step["uses"] for step in jobs["test"]["steps"] if "uses" in step
    }
    assert uses == [test_uses["actions/checkout"], test_uses["astral-sh/setup-uv"]]
    for ref in uses:
        sha = ref.split("@", 1)[1]
        assert len(sha) == 40 and all(char in "0123456789abcdef" for char in sha)
    checkout, setup_uv = (step for step in job["steps"] if "uses" in step)
    assert checkout["with"] == {"persist-credentials": False}
    setup_test = next(step for step in jobs["test"]["steps"] if "astral-sh/setup-uv@" in step.get("uses", ""))
    assert setup_uv["with"]["version"] == setup_test["with"]["version"]


def test_install_shape_job_builds_wheels_without_syncing_the_workspace() -> None:
    job = _jobs()["install-shape"]
    runs = [step["run"] for step in job["steps"] if "run" in step]
    assert runs and all(run.startswith("set -euo pipefail\n") for run in runs)
    assert all(step.get("shell") == "bash" for step in job["steps"] if "run" in step)
    for run in runs:
        assert "uv sync" not in run
        assert "--no-deps" not in run
        assert "--offline" not in run
    build = _steps(job)["Build distribution wheels"]["run"]
    for package in PACKAGES:
        assert (
            f"uv build --package {package} --wheel --build-constraints build-constraints.txt --out-dir dist"
            in build
        )


def test_core_only_shape_runs_check_and_gates_satellite_commands() -> None:
    run = _steps(_jobs()["install-shape"])["Core-only install"]["run"]
    assert 'uv venv "$core"' in run
    assert (
        'uv pip install --python "$core/bin/python" --find-links dist '
        '"dist/mcp_audits-${VERSION}-py3-none-any.whl"'
    ) in run
    assert "mcp_audits_labs" not in run and "mcp_audits_proof" not in run
    assert (
        '"$core/bin/mcp-audit" check --config "$PWD/examples/sandbox/fixtures/synthetic-mcp-config.json"'
        in run
    )
    assert "--config-only --skip-connect --override-config /dev/null" in run
    assert Path("examples/sandbox/fixtures/synthetic-mcp-config.json").is_file()
    assert '"lab agent-ui" "safeforge run"' in run
    assert '[ "$status" -ne 2 ]' in run
    assert LAB_NOTICE in LAB_INSTALL_NOTICE
    assert f'notice="{LAB_NOTICE}"' in run
    assert 'grep -qF "$notice" "$RUNNER_TEMP/stderr.log"' in run
    assert "command -v proof-before-action; then" in run
    for absent in ("mcp-audits-labs", "mcp-audits-proof", "mcp_audit_labs", "proof_before_action"):
        assert absent in run


def test_proof_only_shape_runs_without_core() -> None:
    run = _steps(_jobs()["install-shape"])["Proof-only install"]["run"]
    assert 'uv venv "$proof"' in run
    assert (
        'uv pip install --python "$proof/bin/python" --find-links dist '
        '"dist/mcp_audits_proof-${VERSION}-py3-none-any.whl"'
    ) in run
    assert '"$proof/bin/proof-before-action" --version' in run
    assert '"proof-before-action, version ${VERSION}"' in run
    assert "if \"$proof/bin/python\" -c 'import mcp_audit'; then" in run
    assert 'm.distribution("mcp-audits")' in run
