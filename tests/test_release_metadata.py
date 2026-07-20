"""Release metadata must distinguish a candidate from a published release."""

from __future__ import annotations

import json
import re
import runpy
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest

RELEASE_VERIFIER: dict[str, Any] = runpy.run_path(
    "scripts/verify_release.py",
    run_name="release_verifier_test",
)


def _project_version() -> str:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    assert isinstance(version, str)
    return version


def test_release_version_is_consistent_across_public_surfaces() -> None:
    version = _project_version()
    state = json.loads(Path("docs/release-state.json").read_text(encoding="utf-8"))
    server = json.loads(Path("server.json").read_text(encoding="utf-8"))
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    adoption = Path("docs/ADOPTION-GUIDE.md").read_text(encoding="utf-8")

    assert state == {
        "schema_version": "mcp-audit.release-state.v1",
        "candidate_version": version,
        "published_version": version,
        "previous_version": "2.4.0",
        "status": "release",
    }
    assert server["version"] == state["published_version"]
    assert server["packages"][0]["version"] == state["published_version"]
    assert re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE)
    assert f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/v2.4.0...v{version}" in changelog
    assert f"[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v{version}...HEAD" in changelog
    assert f"saagpatel/MCPAudit@v{version}" in readme
    assert f"saagpatel/MCPAudit@v{version}" in adoption
    assert f"rev: v{version}" in adoption


def test_release_version_is_a_stable_semantic_version() -> None:
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", _project_version())


def test_release_metadata_verifier_passes() -> None:
    result = subprocess.run(
        ["uv", "run", "python", "scripts/verify_release.py"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "release metadata verified for 2.5.0" in result.stdout


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--require-publishable"], "publish verification requires --tag and --commit"),
    ],
)
def test_publishable_metadata_verifier_requires_exact_binding(
    arguments: list[str],
    message: str,
) -> None:
    result = subprocess.run(
        ["uv", "run", "python", "scripts/verify_release.py", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert message in result.stderr


def test_release_state_cannot_keep_a_stale_published_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_release_state",
        lambda: {
            "schema_version": "mcp-audit.release-state.v1",
            "candidate_version": "2.5.0",
            "published_version": "2.4.0",
            "previous_version": "2.4.0",
            "status": "release",
        },
    )

    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="published_version to equal the candidate",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=True)


def test_release_entry_points_are_exact() -> None:
    RELEASE_VERIFIER["_check_entry_points"](
        b"""[console_scripts]
mcp-audit = mcp_audit.cli:main
mcp-audits = mcp_audit.cli:main
proof-before-action = mcp_audit.proof_cli:main
""",
        name="fixture.whl",
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="console entry points",
    ):
        RELEASE_VERIFIER["_check_entry_points"](
            b"[console_scripts]\nmcp-audit = mcp_audit.cli:main\n",
            name="fixture.whl",
        )


def test_release_notes_must_be_finalized_before_publication() -> None:
    check = RELEASE_VERIFIER["_check_release_notes"]

    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="status marker",
    ):
        check("# MCPAudit 2.5.0\n", version="2.5.0", status="release")
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="status marker",
    ):
        check(
            "# MCPAudit 2.5.0\n\n"
            "Release status: candidate\n"
            "Release status: approved\n"
            "Publication decision: GO\n",
            version="2.5.0",
            status="release",
        )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="candidate-only publication language",
    ):
        check(
            "# MCPAudit 2.5.0\n\n"
            "Release status: approved\n"
            "Publication decision: GO\n\n"
            "Public release remains `NO-GO`.\n",
            version="2.5.0",
            status="release",
        )
    check(
        "# MCPAudit 2.5.0\n\nRelease status: approved\nPublication decision: GO\n",
        version="2.5.0",
        status="release",
    )


def test_pypi_environment_requires_independent_non_bypassable_review() -> None:
    verify = RELEASE_VERIFIER["verify_environment_protection"]
    protected: dict[str, Any] = {
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"login": "reviewer"}}],
            }
        ],
    }

    verify(protected)
    for unsafe in (
        {**protected, "can_admins_bypass": True},
        {**protected, "protection_rules": []},
        {
            **protected,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": protected["protection_rules"][0]["reviewers"],
                }
            ],
        },
    ):
        with pytest.raises(RELEASE_VERIFIER["VerificationError"]):
            verify(unsafe)


def test_publication_requires_a_separate_manual_dispatch() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")

    trigger = workflow.split("\npermissions:", maxsplit=1)[0]
    validation_job, build_job = workflow.split("\n  build:\n", maxsplit=1)
    assert "workflow_dispatch:" in trigger
    assert "\n  push:" not in trigger
    assert "commit:" in trigger
    assert "tag:" in trigger
    assert "approval:" not in trigger
    assert "publish-mcp-audits" not in workflow
    assert "validate-dispatch-ref:" in validation_job
    assert 'test "$DISPATCH_REF" = "refs/heads/main"' in validation_job
    assert "needs: validate-dispatch-ref" in build_job


def test_oidc_authority_is_confined_to_post_build_publish_job() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)

    assert "id-token: write" not in build_job
    assert "uv run pytest" in build_job
    assert "scripts/verify_release.py" in build_job
    assert "actions/upload-artifact@" in build_job
    assert "needs: build" in publish_job
    assert "environment: pypi" in publish_job
    assert workflow.count("actions: read") == 2
    assert workflow.count("GH_TOKEN: ${{ github.token }}") == 2
    assert workflow.count("Authorization: Bearer $GH_TOKEN") == 2
    assert "id-token: write" in publish_job
    assert "$RUNNER_TEMP/pypi-environment.json" in workflow
    assert ".can_admins_bypass == false" in publish_job
    assert ".prevent_self_review == true" in publish_job
    assert "required_reviewers" in publish_job
    assert "sha256sum -c SHA256SUMS" in publish_job
    assert publish_job.index("Verify protected PyPI environment") < publish_job.index(
        "sha256sum -c SHA256SUMS"
    )
    assert publish_job.index("sha256sum -c SHA256SUMS") < publish_job.index("pypa/gh-action-pypi-publish@")


def test_candidate_checklist_verifies_exact_built_artifacts_before_install() -> None:
    checklist = Path("docs/RELEASE-CHECKLIST.md").read_text(encoding="utf-8")

    build = checklist.index("uv build --clear")
    verify_artifacts = checklist.index("--dist-dir dist")
    install_wheel = checklist.index("uv pip install")

    assert 'candidate_commit="$(git rev-parse HEAD)"' in checklist
    assert '--commit "$candidate_commit"' in checklist
    assert build < verify_artifacts < install_wheel
