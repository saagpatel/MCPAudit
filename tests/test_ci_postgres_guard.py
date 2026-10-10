"""Exercise the inline CI guard against pytest-shaped JUnit reports."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
import yaml


def test_postgres_ci_uses_local_binaries_without_service_container() -> None:
    workflow: object = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["test"]
    assert isinstance(job, dict)
    assert "services" not in job

    steps = job["steps"]
    assert isinstance(steps, list)
    install_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == "Install PostgreSQL 16 server binaries"
    ]
    assert len(install_steps) == 1
    assert install_steps[0]["run"] == "sudo apt-get install -y postgresql-16"


@pytest.mark.parametrize("root_tag", ["testsuites", "testsuite"])
def test_postgres_guard_accepts_passing_cases(tmp_path: Path, root_tag: str) -> None:
    cases = """
        <testcase classname="research.test_proofos_postgres" name="test_migration" />
        <testcase classname="research.test_proofos_postgres.TestMigration" name="test_rollback" />
        <testcase classname="tests.test_other" name="test_optional"><skipped /></testcase>
    """
    suite = f'<testsuite name="pytest" tests="3" skipped="1">{cases}</testsuite>'
    report = f"<testsuites>{suite}</testsuites>" if root_tag == "testsuites" else suite

    result = _run_guard(tmp_path, report)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "proofos_postgres_guard=2_tests_0_skipped"


@pytest.mark.parametrize(
    "cases",
    [
        "",
        '<testcase classname="tests.test_other" name="test_other" />',
        '<testcase classname="research.test_proofos_postgres_extra" name="test_other" />',
        '<testcase name="test_migration" />',
    ],
    ids=["empty", "other-module", "module-prefix-lookalike", "missing-classname"],
)
def test_postgres_guard_rejects_missing_cases(tmp_path: Path, cases: str) -> None:
    # Even a matching suite name cannot substitute for the module's testcases.
    report = f'<testsuites><testsuite name="research.test_proofos_postgres">{cases}</testsuite></testsuites>'

    result = _run_guard(tmp_path, report)

    assert result.returncode != 0
    assert "ProofOS PostgreSQL test cases missing" in result.stderr
    assert not result.stdout


@pytest.mark.parametrize("include_passing_case", [False, True], ids=["all-skipped", "partly-skipped"])
def test_postgres_guard_rejects_skipped_cases(tmp_path: Path, include_passing_case: bool) -> None:
    cases = """
        <testcase classname="research.test_proofos_postgres" name="test_migration">
            <skipped type="pytest.skip" message="local fixture unavailable" />
        </testcase>
    """
    if include_passing_case:
        cases += '<testcase classname="research.test_proofos_postgres" name="test_rollback" />'
    report = f'<testsuites><testsuite name="pytest">{cases}</testsuite></testsuites>'

    result = _run_guard(tmp_path, report)

    assert result.returncode != 0
    assert "inadmissible ProofOS PostgreSQL result" in result.stderr
    assert "'skipped': 1" in result.stderr
    assert not result.stdout


def _run_guard(tmp_path: Path, report: str) -> subprocess.CompletedProcess[str]:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    guard = dedent(workflow.split("uv run python - <<'PY'\n", maxsplit=1)[1].split("\n          PY")[0])
    results_path = tmp_path / "unit-results.xml"
    results_path.write_text(report, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-c", guard],
        env={**os.environ, "RESULTS_PATH": str(results_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
