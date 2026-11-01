"""Release metadata must distinguish a candidate from a published release."""

from __future__ import annotations

import json
import re
import runpy
import shlex
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import cli, proof_cli

RELEASE_VERIFIER: dict[str, Any] = runpy.run_path(
    "scripts/verify_release.py",
    run_name="release_verifier_test",
)


def _project_version() -> str:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    assert isinstance(version, str)
    return version


def test_release_versions_are_consistent_across_surfaces() -> None:
    state = json.loads(Path("docs/release-state.json").read_text(encoding="utf-8"))
    assert isinstance(state, dict)
    version = state["candidate_version"]
    published_version = state["published_version"]
    previous_version = state["previous_version"]
    status = state["status"]
    assert isinstance(version, str)
    assert isinstance(published_version, str)
    assert isinstance(previous_version, str)
    assert status in {"candidate", "release"}
    server = json.loads(Path("server.json").read_text(encoding="utf-8"))
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    adoption = Path("docs/ADOPTION-GUIDE.md").read_text(encoding="utf-8")

    assert _project_version() == version
    if status == "release":
        assert published_version == version
        assert re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE)
        assert f"## [{version}] - Unreleased" not in changelog
        assert f"[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v{version}...HEAD" in changelog
        assert (
            f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/v{previous_version}...v{version}"
            in changelog
        )
    else:
        assert published_version != version
        assert previous_version == published_version
        assert f"## [{version}] - Unreleased" in changelog
        assert (
            f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/v{published_version}...HEAD"
            in changelog
        )
    assert server["version"] == published_version
    assert server["packages"][0]["version"] == published_version
    assert "## [2.7.0] - 2026-08-14" in changelog
    assert "## [2.8.0] - 2026-10-06" in changelog
    assert "## [2.8.1] - 2026-10-06" in changelog
    assert "## [2.9.0] - 2026-10-10" in changelog
    assert "## [2.10.1] - 2026-10-11" in changelog
    assert "## [2.11.0] - 2026-10-12" in changelog
    assert "## [2.12.0] - 2026-10-12" in changelog
    assert "[2.10.0]: https://github.com/saagpatel/MCPAudit/compare/v2.9.0...v2.10.0" in changelog
    assert "[2.8.0]: https://github.com/saagpatel/MCPAudit/compare/v2.7.0...v2.8.0" in changelog
    assert f"saagpatel/MCPAudit@v{published_version}" in readme
    assert f"saagpatel/MCPAudit@v{published_version}" in adoption
    assert f"rev: v{published_version}" in adoption


def test_release_version_is_a_stable_semantic_version() -> None:
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", _project_version())


def test_cli_versions_match_project_metadata() -> None:
    version = _project_version()
    runner = CliRunner()

    audit = runner.invoke(cli.main, ["--version"])
    proof = runner.invoke(proof_cli.main, ["--version"])
    assert audit.exit_code == 0
    assert proof.exit_code == 0
    assert audit.output.strip() == f"mcp-audit, version {version}"
    assert proof.stdout.strip() == f"proof-before-action, version {version}"


def test_release_metadata_verifier_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_release.py"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert f"release metadata verified for {_project_version()}" in result.stdout


def test_release_verifier_requires_public_tag_in_precommit_usage_comment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_text = cast(Callable[[str], str], RELEASE_VERIFIER["_read_text"])

    def read_with_stale_precommit_tag(path: str) -> str:
        content = read_text(path)
        if path == ".pre-commit-hooks.yaml":
            stale = re.sub(r"rev: v\d+\.\d+\.\d+", "rev: v0.0.0", content)
            assert stale != content
            return stale
        return content

    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__, "_read_text", read_with_stale_precommit_tag
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="pre-commit usage comment does not reference the usable public release",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_release_state_cannot_keep_a_stale_published_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_release_state",
        lambda: {
            "schema_version": "mcp-audit.release-state.v1",
            "candidate_version": _project_version(),
            "published_version": "2.10.0",
            "previous_version": "2.10.0",
            "status": "release",
        },
    )

    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="published_version to equal the candidate",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=True)


def test_candidate_version_cannot_equal_published_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_release_state",
        lambda: {
            "schema_version": "mcp-audit.release-state.v1",
            "candidate_version": _project_version(),
            "published_version": _project_version(),
            "previous_version": _project_version(),
            "status": "candidate",
        },
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="candidate version must differ from the published version",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_candidate_previous_version_must_equal_published_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_release_state",
        lambda: {
            "schema_version": "mcp-audit.release-state.v1",
            "candidate_version": _project_version(),
            "published_version": "2.10.0",
            "previous_version": "2.9.0",
            "status": "candidate",
        },
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="candidate previous_version must equal the published version",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_lock_version_must_equal_project_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_locked_project_version",
        lambda: "2.6.0",
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="uv.lock project version does not match project.version",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_candidate_state_is_never_publishable(tmp_path: Path) -> None:
    """Pin the candidate refusal against a self-consistent synthetic candidate tree.

    Every surface below has to agree with the injected candidate state, because
    the server.json, action-ref, dependency-floor, release-note, and changelog
    checks all run before the publishable gate is reached.
    """
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "mcp-audits"\nversion = "2.6.0"\n'
        'dependencies = ["mcp>=2.2.0,<3.0", "cryptography>=50.0.0,<51.0", '
        '"click>=8.3.3,<9.0", "anyio>=4.14.2"]\n'
        '[project.scripts]\nmcp-audit = "mcp_audit.cli:main"\n'
        'mcp-audits = "mcp_audit.cli:main"\n'
        'proof-before-action = "mcp_audit.proof_cli:main"\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "mcp-audits"\nversion = "2.6.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "docs/release-state.json").write_text(
        json.dumps(
            {
                "schema_version": "mcp-audit.release-state.v1",
                "candidate_version": "2.6.0",
                "published_version": "2.5.0",
                "previous_version": "2.5.0",
                "status": "candidate",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "name": "io.github.saagpatel/mcp-audit",
                "version": "2.5.0",
                "repository": {"url": "https://github.com/saagpatel/MCPAudit", "source": "github"},
                "packages": [
                    {
                        "registryType": "pypi",
                        "registryBaseUrl": "https://pypi.org",
                        "identifier": "mcp-audits",
                        "version": "2.5.0",
                        "runtimeHint": "uvx",
                        "transport": {"type": "stdio"},
                        "packageArguments": [{"type": "positional", "value": "serve"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "CHANGELOG.md").write_text(
        "## [2.6.0] - Unreleased\n\n### Release boundary details\n\n"
        "MCPAudit 2.6.0\nRelease status: candidate\nPublication decision: NO-GO\n"
        "Retain mcp-audits==2.5.0.\n\n"
        "[2.6.0]: https://github.com/saagpatel/MCPAudit/compare/v2.5.0...HEAD\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("uses: saagpatel/MCPAudit@v2.5.0\n", encoding="utf-8")
    (tmp_path / ".pre-commit-hooks.yaml").write_text("#       rev: v2.5.0\n", encoding="utf-8")
    (tmp_path / "docs/ADOPTION-GUIDE.md").write_text(
        "uses: saagpatel/MCPAudit@v2.5.0\nrev: v2.5.0\n", encoding="utf-8"
    )
    original_root = RELEASE_VERIFIER["verify_metadata"].__globals__["ROOT"]
    RELEASE_VERIFIER["_set_root"](tmp_path)
    try:
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)
        with pytest.raises(
            RELEASE_VERIFIER["VerificationError"],
            match="candidate state is intentionally non-publishable",
        ):
            RELEASE_VERIFIER["verify_metadata"](require_publishable=True)
    finally:
        RELEASE_VERIFIER["_set_root"](original_root)


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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", "wrong-distribution", "distribution name"),
        (
            "scripts",
            {"mcp-audit": "mcp_audit.cli:main"},
            "console entry points",
        ),
    ],
)
def test_source_project_identity_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    original_project = RELEASE_VERIFIER["_project"]()
    changed_project = {**original_project, field: value}
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_project",
        lambda: changed_project,
    )

    with pytest.raises(RELEASE_VERIFIER["VerificationError"], match=message):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_mcp_major_bound_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    original_project = RELEASE_VERIFIER["_project"]()
    dependencies = list(original_project["dependencies"])
    dependencies.remove("mcp>=2.2.0,<3.0")
    dependencies.append("mcp>=2.2.0")
    monkeypatch.setitem(
        RELEASE_VERIFIER["verify_metadata"].__globals__,
        "_project",
        lambda: {**original_project, "dependencies": dependencies},
    )

    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="tested MCP SDK range",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


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


def test_pypi_environment_requires_named_solo_maintainer_review() -> None:
    verify = RELEASE_VERIFIER["verify_environment_protection"]
    protected: dict[str, Any] = {
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": {"login": "saagpatel"}}],
            }
        ],
    }

    branches = {"branch_policies": [{"name": "main", "type": "branch"}]}
    verify(protected, branches)
    stronger = {
        **protected,
        "protection_rules": [{**protected["protection_rules"][0], "prevent_self_review": True}],
    }
    verify(stronger, branches)
    for unsafe in (
        {**protected, "can_admins_bypass": True},
        {**protected, "protection_rules": []},
        {
            **protected,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [{"type": "User", "reviewer": {"login": "other-reviewer"}}],
                }
            ],
        },
    ):
        with pytest.raises(RELEASE_VERIFIER["VerificationError"]):
            verify(unsafe, branches)
    unsafe_branch_cases: tuple[object, ...] = (
        None,
        {"branch_policies": []},
        {"branch_policies": [{"name": "*", "type": "branch"}]},
    )
    for unsafe_branches in unsafe_branch_cases:
        with pytest.raises(RELEASE_VERIFIER["VerificationError"]):
            verify(protected, unsafe_branches)


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
    assert 'test "$DISPATCH_REF" = "refs/heads/release/2.x"' in validation_job
    assert "needs: validate-dispatch-ref" in build_job


def test_publish_gate_prepares_proof_before_action_test_image() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, _publish_job = workflow.split("\n  publish:\n", maxsplit=1)
    pre_trust = build_job.split("Install locked dependencies", maxsplit=1)[0]

    assert "Checkout release controls" in build_job
    assert "Checkout exact release source" in build_job
    assert "path: release-controls" in build_job
    assert "path: release-source" in build_job
    assert "../release-controls/scripts/verify_release.py" in build_job
    assert "python ../release-controls/scripts/verify_release.py" in pre_trust
    assert "uv run python ../release-controls/scripts/verify_release.py" not in pre_trust
    assert "--root ." in build_job
    assert "working-directory: release-source" in build_job
    assert "Prepare Proof Before Action test image" in build_job
    assert "docker image inspect node:24-slim" in build_job
    assert "docker pull node:24-slim" in build_job
    assert "docker image inspect --format '{{.Id}}' node:24-slim" in build_job
    assert build_job.index("Prepare Proof Before Action test image") < build_job.index("uv run pytest")


def test_oidc_authority_is_confined_to_post_build_publish_job() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)

    assert "id-token: write" not in build_job
    assert "uv run pytest" in build_job
    assert "scripts/verify_release.py" in build_job
    assert "actions/upload-artifact@" in build_job
    assert "needs: [build, consumer-smoke]" in publish_job
    assert "environment: pypi-2x\n" in publish_job
    assert workflow.count("actions: read") == 3
    assert workflow.count("GH_TOKEN: ${{ github.token }}") == 2
    assert workflow.count("Authorization: Bearer $GH_TOKEN") == 4
    assert "id-token: write" in publish_job
    assert "$RUNNER_TEMP/pypi-environment.json" in workflow
    assert "--publication-check environment" in publish_job
    assert "--branch-policies-json" in publish_job
    assert "--publication-check artifacts" in publish_job
    assert publish_job.index("Verify protected PyPI environment") < publish_job.index(
        "--publication-check artifacts"
    )
    assert publish_job.index("--publication-check artifacts") < publish_job.index(
        "pypa/gh-action-pypi-publish@"
    )


def test_publish_gate_runs_corpus_and_exact_distribution_install_smokes() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, _publish_job = workflow.split("\n  publish:\n", maxsplit=1)

    assert "tests/validation/validate_patterns.py" in build_job
    assert "Smoke-install exact wheel and sdist" in build_job
    assert 'for package in "$wheel" "$sdist"' in build_job
    assert 'release_version="${RELEASE_TAG#v}"' in build_job
    assert "mcp-audit, version $release_version" in build_job
    assert "proof-before-action, version $release_version" in build_job
    assert '"$smoke/bin/python" -I scripts/smoke_installed_artifact.py' in build_job


def test_registry_publication_is_manual_pypi_first_and_oidc_confined() -> None:
    workflow = Path(".github/workflows/publish-mcp-registry.yml").read_text(encoding="utf-8")
    validate_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)
    trigger = workflow.split("\npermissions:", maxsplit=1)[0]

    assert "workflow_dispatch:" in trigger
    assert "\n  push:" not in trigger
    assert "pull_request_target" not in workflow
    assert "actions: read" in validate_job
    assert "id-token: write" not in validate_job
    assert "Checkout trusted release controls" in validate_job
    assert "Checkout exact release source" in validate_job
    assert "path: release-controls" in validate_job
    assert "path: release-source" in validate_job
    assert "../release-controls/scripts/verify_release.py" in validate_job
    assert "python ../release-controls/scripts/verify_release.py" in validate_job
    assert "uv run python ../release-controls/scripts/verify_release.py" not in validate_job
    assert "--root ." in validate_job
    assert "working-directory: release-source" in validate_job
    assert "https://pypi.org/pypi/mcp-audits/$release_version/json" in validate_job
    assert "environments/pypi-2x/deployment-branch-policies" in validate_job
    assert 'mcp-publisher" validate server.json' in validate_job
    assert "needs: validate" in publish_job
    assert "environment: pypi-2x\n" in publish_job
    assert "id-token: write" in publish_job
    assert "login github-oidc" in publish_job
    assert 'mcp-publisher" publish release-source/server.json' in publish_job
    assert 'test "$(git -C release-source rev-parse HEAD)" = "$RELEASE_COMMIT"' in publish_job
    assert "/versions/$release_version" in publish_job
    assert 'for selector in "$release_version" latest' not in publish_job
    assert "/versions/latest" not in publish_job
    assert "--publication-check registry" in publish_job
    assert publish_job.index("--publication-check descriptor") < publish_job.index("login github-oidc")
    assert "--publication-check pypi" in publish_job
    assert "--manifest-sha256" in publish_job


@pytest.mark.parametrize("filename", ["publish.yml", "publish-mcp-registry.yml"])
@pytest.mark.parametrize(
    ("ref", "accepted"),
    [
        ("refs/heads/release/2.x", True),
        ("refs/heads/main", False),
        ("refs/heads/feature", False),
        ("refs/tags/v2.12.1", False),
    ],
)
def test_maintenance_dispatch_ref_is_exclusive(filename: str, ref: str, accepted: bool) -> None:
    workflow = yaml.safe_load(Path(".github/workflows", filename).read_text())
    first_job = next(iter(workflow["jobs"].values()))
    guard = first_job["steps"][0]
    assert guard["env"]["DISPATCH_REF"] == "${{ github.ref }}"
    result = subprocess.run(
        ["bash", "-c", guard["run"]],
        env={"DISPATCH_REF": ref},
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert (result.returncode == 0) is accepted, result.stderr


@pytest.mark.parametrize("filename", ["publish.yml", "publish-mcp-registry.yml"])
def test_maintenance_publication_binds_every_verifier_and_environment(filename: str) -> None:
    text = Path(".github/workflows", filename).read_text()
    workflow = yaml.safe_load(text)
    assert workflow["jobs"]["publish"]["environment"] == "pypi-2x"
    assert "environments/pypi-2x" in text
    assert re.search(r"environments/pypi(?:/|\")", text) is None
    if filename == "publish-mcp-registry.yml":
        assert workflow["env"]["RELEASE_ENVIRONMENT"] == "pypi-2x"
        assert "for endpoint in pypi-2x pypi-2x/deployment-branch-policies; do" in text
        assert '--environment-json "$RUNNER_TEMP/pypi-2x.json"' in text

    verifier_commands = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            for line in step.get("run", "").replace("\\\n", " ").splitlines():
                if "scripts/verify_release.py" in line:
                    command = shlex.split(line)
                    verifier_commands.append(command)
                    assert command.count("--release-branch") == 1
                    assert command[command.index("--release-branch") + 1] == "release/2.x"
                    # The verifier's default is the single-distribution 2.x contract.
                    assert "--distributions" not in command
                    if "--require-publishable" in command:
                        assert "--tag" in command
                        assert "--commit" in command
    assert verifier_commands
    authorization = verifier_commands[0]
    assert "--require-publishable" in authorization
    assert authorization[authorization.index("--tag") + 1] == "$RELEASE_TAG"
    assert authorization[authorization.index("--commit") + 1] == "$RELEASE_COMMIT"
    assert "git fetch --force --tags origin release/2.x\n" in text
    assert "origin main" not in text
    assert "mcp-audits-labs" not in text
    assert "mcp-audits-proof" not in text


@pytest.mark.parametrize("filename", ["ci.yml", "codeql.yml"])
@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_maintenance_branch_has_ci_and_codeql_coverage(filename: str, event: str) -> None:
    workflow = yaml.load(Path(".github/workflows", filename).read_text(), Loader=yaml.BaseLoader)
    assert "release/2.x" in workflow["on"][event]["branches"]


def test_registry_publisher_binary_is_version_and_hash_pinned() -> None:
    workflow = Path(".github/workflows/publish-mcp-registry.yml").read_text(encoding="utf-8")

    assert "MCP_PUBLISHER_VERSION: v1.8.1" in workflow
    assert (
        "MCP_PUBLISHER_SHA256: a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc"
    ) in workflow
    assert workflow.count("sha256sum --check") == 2


def test_candidate_checklist_verifies_exact_built_artifacts_before_install() -> None:
    checklist = Path("maintainers/RELEASE-CHECKLIST.md").read_text(encoding="utf-8")

    build = checklist.index("uv build --clear")
    verify_artifacts = checklist.index("--dist-dir dist")
    install_wheel = checklist.index("uv pip install")

    assert 'candidate_commit="$(git rev-parse HEAD)"' in checklist
    assert '--commit "$candidate_commit"' in checklist
    assert build < verify_artifacts < install_wheel
