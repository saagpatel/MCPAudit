"""Release metadata must distinguish a candidate from a published release."""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner
from proof_before_action import proof_cli

from mcp_audit import cli
from scripts import verify_release as release
from tests.test_release_supply import _release_root

RELEASE_VERIFIER: dict[str, Any] = runpy.run_path(
    "scripts/verify_release.py",
    run_name="release_verifier_test",
)
CONTRACT = Path("release/distributions.json")
TRAIN = RELEASE_VERIFIER["load_distributions"](CONTRACT)


@pytest.fixture(autouse=True)
def split_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(RELEASE_VERIFIER["verify_metadata"].__globals__, "DISTRIBUTIONS", TRAIN)


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
    for item in TRAIN:
        project = tomllib.loads(Path(item.project).read_text())["project"]
        assert project["name"] == item.name
        assert project["version"] == version
        assert project.get("scripts", {}) == item.scripts
    lock = tomllib.loads(Path("uv.lock").read_text())
    for item in TRAIN:
        assert [entry["version"] for entry in lock["package"] if entry["name"] == item.name] == [version]
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
        [sys.executable, "scripts/verify_release.py", "--distributions", str(CONTRACT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert f"release metadata verified for {_project_version()}" in result.stdout


@pytest.mark.parametrize(
    "mode", ["metadata", "environment", "artifacts", "pypi", "descriptor", "registry", "tag"]
)
@pytest.mark.parametrize("contract", ["missing", "unsplit"])
@pytest.mark.parametrize("version", ["3.0.0", "4.0.0"])
def test_3x_cli_rejects_missing_or_unsplit_contract(
    tmp_path: Path, mode: str, contract: str, version: str
) -> None:
    # 4.x must not inherit the 2.x unsplit default: every non-2.x line is split.
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion="{version}"\n')
    command = [sys.executable, "scripts/verify_release.py", "--root", str(tmp_path)]
    if mode != "metadata":
        command.extend(["--publication-check", mode, "--tag", f"v{version}", "--commit", "a" * 40])
    if contract == "unsplit":
        path = tmp_path / "unsplit.json"
        path.write_text(json.dumps([TRAIN[0]._asdict()]))
        command.extend(["--distributions", str(path)])
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 1
    assert "3.x and later require an explicit three-distribution contract" in result.stderr


def test_only_2x_versions_may_stay_unsplit() -> None:
    assert not release._is_split_version("2.12.0")
    for version in ("3.0.0", "3.9.42", "4.0.0", "10.1.0"):
        assert release._is_split_version(version)


@pytest.mark.parametrize("version", ["3.0.0", "3.9.42", "4.0.0"])
def test_3x_library_metadata_and_manifest_reject_unsplit(
    version: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "DISTRIBUTIONS", (release.DISTRIBUTIONS[0],))
    monkeypatch.setattr(release, "_version", lambda: version)
    with pytest.raises(release.VerificationError, match="three-distribution"):
        release.verify_metadata(require_publishable=False)
    with pytest.raises(release.VerificationError, match="three-distribution"):
        release.verify_manifest(
            {
                "schema_version": release.MANIFEST_SCHEMA,
                "version": version,
                "commit": "a" * 40,
                "workflow_sha": "b" * 40,
                "files": {},
            },
            version=version,
            commit="a" * 40,
        )


@pytest.mark.parametrize("mutation", ["none", "source", "controls", "input", "commit", "missing"])
def test_release_contract_is_identical_and_commit_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    raw = CONTRACT.read_bytes()
    source, controls = tmp_path / "source", tmp_path / "controls"
    for root in (source, controls):
        (root / "release").mkdir(parents=True)
        (root / release.CONTRACT_PATH).write_bytes(raw)
    supplied = tmp_path / "contract.json"
    supplied.write_bytes(raw)
    if mutation in {"source", "controls"}:
        root = source if mutation == "source" else controls
        (root / release.CONTRACT_PATH).write_bytes(raw + b"\n")
    elif mutation == "input":
        supplied.write_bytes(raw + b"\n")
    elif mutation == "missing":
        (source / release.CONTRACT_PATH).unlink()
    monkeypatch.setattr(release, "ROOT", source)
    monkeypatch.setattr(release, "CONTROL_ROOT", controls)

    def committed(commit: str, paths: list[str]) -> dict[str, bytes]:
        assert commit == "a" * 40 and paths == [release.CONTRACT_PATH]
        return {release.CONTRACT_PATH: raw + (b"\n" if mutation == "commit" else b"")}

    monkeypatch.setattr(release, "_commit_files", committed)
    if mutation == "none":
        release.verify_contract_binding(supplied, commit="a" * 40)
    else:
        with pytest.raises((release.VerificationError, OSError)):
            release.verify_contract_binding(supplied, commit="a" * 40)


@pytest.mark.parametrize("published", [False, True], ids=["before", "after"])
@pytest.mark.parametrize("tag_state", ["absent", "approved", "other"])
@pytest.mark.parametrize("version", ["3.0.0", "4.0.0"])
def test_3x_git_binding_is_commit_first(
    monkeypatch: pytest.MonkeyPatch, published: bool, tag_state: str, version: str
) -> None:
    commit = "a" * 40
    tag = f"v{version}"
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        calls.append(args)
        if args == ("rev-parse", "HEAD"):
            return commit
        if args == ("tag", "--list", tag):
            return "" if tag_state == "absent" else tag
        if args == ("rev-parse", f"refs/tags/{tag}^{{commit}}"):
            if tag_state == "absent":
                raise release.VerificationError("tag is missing")
            return commit if tag_state == "approved" else "b" * 40
        return ""

    monkeypatch.setattr(release, "DISTRIBUTIONS", release.load_distributions(CONTRACT))
    monkeypatch.setattr(release, "_version", lambda: version)
    monkeypatch.setattr(release, "_run_git", git)
    monkeypatch.setattr(
        release, "_commit_files", lambda *args: {release.CONTRACT_PATH: CONTRACT.read_bytes()}
    )
    valid = tag_state == ("approved" if published else "absent")
    if valid:
        release.verify_git_binding(
            tag=tag if published else None, commit=commit, require_landed=True, published=published
        )
        assert ("merge-base", "--is-ancestor", commit, "origin/main") in calls
    else:
        with pytest.raises(release.VerificationError):
            release.verify_git_binding(
                tag=tag if published else None,
                commit=commit,
                require_landed=True,
                published=published,
            )


@pytest.mark.parametrize("version", ["3.0.0", "4.0.0"])
def test_3x_publishable_check_accepts_commit_without_tag(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_release.py",
            "--require-publishable",
            "--commit",
            "a" * 40,
            "--distributions",
            str(CONTRACT),
            "--environment-json",
            "unused.json",
        ],
    )
    monkeypatch.setattr(release, "_version", lambda: version)
    monkeypatch.setattr(release, "verify_metadata", lambda **kwargs: (version, {}))
    observed: list[dict[str, object]] = []
    monkeypatch.setattr(release, "verify_git_binding", lambda **kwargs: observed.append(kwargs))
    monkeypatch.setattr(release, "_load_json", lambda path: {})
    monkeypatch.setattr(release, "verify_environment_protection", lambda *args: None)
    monkeypatch.setattr(release, "DISTRIBUTIONS", release.DISTRIBUTIONS)
    assert release.main() == 0
    assert observed == [{"tag": None, "commit": "a" * 40, "require_landed": True, "published": False}]


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
        lambda distribution="mcp-audits": "2.6.0" if distribution == "mcp-audits" else _project_version(),
    )
    with pytest.raises(
        RELEASE_VERIFIER["VerificationError"],
        match="uv.lock project version does not match project.version",
    ):
        RELEASE_VERIFIER["verify_metadata"](require_publishable=False)


def test_candidate_state_is_never_publishable(tmp_path: Path) -> None:
    """Pin the candidate refusal against a self-consistent synthetic 3.x split tree.

    Every surface below has to agree with the injected candidate state, because
    the server.json, action-ref, dependency-floor, release-note, and changelog
    checks all run before the publishable gate is reached.
    """
    (tmp_path / "docs").mkdir()
    (tmp_path / "release").mkdir()
    (tmp_path / "release/distributions.json").write_bytes(CONTRACT.read_bytes())
    for item in TRAIN:
        project = tmp_path / item.project
        project.parent.mkdir(parents=True, exist_ok=True)
        project.write_text(Path(item.project).read_text().replace(_project_version(), "3.0.0"))
    (tmp_path / "uv.lock").write_text(
        "version = 1\n" + "".join(f'[[package]]\nname="{item.name}"\nversion="3.0.0"\n' for item in TRAIN),
        encoding="utf-8",
    )
    (tmp_path / "docs/release-state.json").write_text(
        json.dumps(
            {
                "schema_version": "mcp-audit.release-state.v1",
                "candidate_version": "3.0.0",
                "published_version": "2.12.0",
                "previous_version": "2.12.0",
                "status": "candidate",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "name": "io.github.saagpatel/mcp-audit",
                "version": "2.12.0",
                "repository": {"url": "https://github.com/saagpatel/MCPAudit", "source": "github"},
                "packages": [
                    {
                        "registryType": "pypi",
                        "registryBaseUrl": "https://pypi.org",
                        "identifier": "mcp-audits",
                        "version": "2.12.0",
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
        "## [3.0.0] - Unreleased\n\n### Release boundary details\n\n"
        "MCPAudit 3.0.0\nRelease status: candidate\nPublication decision: NO-GO\n"
        "Retain mcp-audits==2.12.0.\n\n"
        "[3.0.0]: https://github.com/saagpatel/MCPAudit/compare/v2.12.0...HEAD\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("uses: saagpatel/MCPAudit@v2.12.0\n", encoding="utf-8")
    (tmp_path / ".pre-commit-hooks.yaml").write_text("#       rev: v2.12.0\n", encoding="utf-8")
    (tmp_path / "docs/ADOPTION-GUIDE.md").write_text(
        "uses: saagpatel/MCPAudit@v2.12.0\nrev: v2.12.0\n", encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_release.py",
            "--root",
            str(tmp_path),
            "--distributions",
            str(CONTRACT),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
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
    assert "version:" in trigger
    assert "tag:" not in trigger
    assert "approval:" not in trigger
    assert "publish-mcp-audits" not in workflow
    assert "validate-dispatch-ref:" in validation_job
    assert 'test "$DISPATCH_REF" = "refs/heads/main"' in validation_job
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
    assert "uv run --no-project --with packaging==26.0 python" in pre_trust
    assert "--root ." in build_job
    assert "working-directory: release-source" in build_job
    assert "Prepare Proof Before Action test image" in build_job
    assert "docker image inspect node:24-slim" in build_job
    assert "docker pull node:24-slim" in build_job
    assert "docker image inspect --format '{{.Id}}' node:24-slim" in build_job
    assert build_job.index("Prepare Proof Before Action test image") < build_job.index(
        "uv run --all-packages pytest"
    )


def test_oidc_authority_is_confined_to_post_build_publish_job() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)

    assert "id-token: write" not in build_job
    assert "uv run --all-packages pytest" in build_job
    assert "scripts/verify_release.py" in build_job
    assert "actions/upload-artifact@" in build_job
    assert "needs: [validate-dispatch-ref, build, consumer-smoke, resume]" in publish_job
    assert "needs.consumer-smoke.result == 'success'" in publish_job
    assert "inputs.resume && needs.resume.result == 'success'" in publish_job
    assert "environment: pypi" in publish_job
    assert workflow.count("actions: read") == 3
    assert workflow.count("GH_TOKEN: ${{ github.token }}") == 4
    assert workflow.count("Authorization: Bearer $GH_TOKEN") == 6
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
    assert "Smoke-install every wheel, sdist and exact-pinned extra offline" in build_job
    assert "python scripts/smoke_release.py --distributions release/distributions.json" in build_job
    assert "--dependencies" in build_job
    smoke = Path("scripts/smoke_release.py").read_text(encoding="utf-8")
    assert "release.distribution_names(version, item.name)" in smoke
    assert 'f"mcp-audit, version {version}"' in smoke
    assert "elif proof.exists():" in smoke
    assert 'f"proof-before-action, version {version}"' in smoke
    assert '"smoke_installed_artifact.py"' in smoke


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
    assert validate_job.count('"https://pypi.org/pypi/$distribution/$release_version/json"') == 1
    assert publish_job.count('"https://pypi.org/pypi/$distribution/$release_version/json"') == 1
    assert validate_job.count("for distribution in $(python -c") == 1
    assert publish_job.count("for distribution in $(python -c") == 1
    assert 'item["name"]: json.loads' in validate_job
    assert 'item["name"]: json.loads' in publish_job
    assert '"$RUNNER_TEMP/pypi-readback.json"' in validate_job
    assert '"$RUNNER_TEMP/pypi-readback.json"' in publish_job
    assert "environments/pypi/deployment-branch-policies" in validate_job
    assert 'mcp-publisher" validate server.json' in validate_job
    assert "needs: validate" in publish_job
    assert "environment: pypi" in publish_job
    assert "id-token: write" in publish_job
    assert "login github-oidc" in publish_job
    assert 'mcp-publisher" publish release-source/server.json' in publish_job
    assert 'test "$(git -C release-source rev-parse HEAD)" = "$RELEASE_COMMIT"' in publish_job
    assert "/versions/$selector" in publish_job
    assert "--publication-check registry" in publish_job
    assert publish_job.index("--publication-check descriptor") < publish_job.index("login github-oidc")
    assert "--publication-check pypi" in publish_job
    assert "--manifest-sha256" in publish_job


REGISTRY_WORKFLOW = Path(".github/workflows/publish-mcp-registry.yml")
REGISTRY_COMMIT = "1" * 40
REGISTRY_WORKFLOW_SHA = "2" * 40


def _registry_steps() -> list[tuple[str, dict[str, Any]]]:
    import yaml

    workflow = yaml.safe_load(REGISTRY_WORKFLOW.read_text(encoding="utf-8"))
    return [
        (job_name, step)
        for job_name, job in workflow["jobs"].items()
        for step in job["steps"]
        if isinstance(step.get("run"), str)
    ]


def _verifier_invocations(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    return [line.strip() for line in joined.splitlines() if "verify_release.py" in line]


def test_every_registry_verifier_invocation_passes_the_release_contract() -> None:
    invocations = [
        (step.get("working-directory", "."), command)
        for _job, step in _registry_steps()
        for command in _verifier_invocations(step["run"])
    ]

    # validate: metadata, pypi, descriptor; publish: environment, pypi, descriptor, registry.
    assert len(invocations) == 7
    for working_directory, command in invocations:
        values = re.findall(r"--distributions (\S+)", command)
        assert len(values) == 1, command
        resolved = Path(os.path.normpath(Path(working_directory) / values[0]))
        assert resolved == Path("release-controls/release/distributions.json"), command
    rooted = [command for _wd, command in invocations if "--root ." in command]
    assert len(rooted) == 1
    assert "--distributions ../release-controls/release/distributions.json" in rooted[0]


@pytest.mark.parametrize("drift", [False, True])
def test_rooted_registry_metadata_step_binds_source_to_controls_contract(tmp_path: Path, drift: bool) -> None:
    # The tag must equal the checkout version, so the v3.0.0 run binds a 3.0.0 source stub.
    source = _release_root(tmp_path / "release-source", "3.0.0")
    if drift:
        with (source / release.CONTRACT_PATH).open("ab") as stream:
            stream.write(b" ")

    result = subprocess.run(
        [
            sys.executable,
            str(Path.cwd() / "scripts/verify_release.py"),
            "--root",
            ".",
            "--distributions",
            str(Path.cwd() / CONTRACT),
            "--tag",
            "v3.0.0",
            "--commit",
            REGISTRY_COMMIT,
            "--require-publishable",
        ],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode != 0
    assert "does not match the checkout project.version" not in result.stderr, result.stderr
    binding = "source and release-controls distribution contracts must be byte-identical"
    assert (binding in result.stderr) is drift, result.stderr


def _fixture_git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.mark.parametrize("tag_state", ["approved", "other", "absent"])
def test_registry_metadata_step_requires_3x_tag_at_approved_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tag_state: str
) -> None:
    """The 3.x Registry run follows the owner's post-PyPI tag, so the tag must exist at the commit."""
    [(_, step)] = [
        (name, step)
        for name, step in _registry_steps()
        if name == "validate" and step.get("name") == "Verify tag, commit, main, and release metadata"
    ]
    assert step["working-directory"] == "release-source"
    assert "git fetch --force --tags origin main" in step["run"]
    [command] = _verifier_invocations(step["run"])
    assert "--tag-published" in command

    version = "3.0.0"
    tag = f"v{version}"
    source = tmp_path / "release-source"
    (source / "release").mkdir(parents=True)
    (tmp_path / "release-controls").symlink_to(Path.cwd(), target_is_directory=True)
    (source / "pyproject.toml").write_text(f'[project]\nname = "mcp-audits"\nversion = "{version}"\n')
    (source / "release/distributions.json").write_bytes(CONTRACT.read_bytes())
    _fixture_git(source, "init", "-q")
    _fixture_git(source, "add", "pyproject.toml", "release/distributions.json")
    _fixture_git(source, "commit", "-q", "-m", "approved")
    commit = _fixture_git(source, "rev-parse", "HEAD")
    _fixture_git(source, "commit", "-q", "--allow-empty", "-m", "later")
    other = _fixture_git(source, "rev-parse", "HEAD")
    _fixture_git(source, "update-ref", "refs/remotes/origin/main", other)
    _fixture_git(source, "checkout", "-q", "--detach", commit)
    if tag_state != "absent":
        _fixture_git(source, "tag", tag, commit if tag_state == "approved" else other)

    runner_temp = tmp_path / "rt"
    substitutions = {
        '"$RELEASE_TAG"': tag,
        '"$RELEASE_COMMIT"': commit,
        '"$RUNNER_TEMP/pypi-environment.json"': str(runner_temp / "pypi-environment.json"),
        '"$RUNNER_TEMP/pypi-branches.json"': str(runner_temp / "pypi-branches.json"),
    }
    argv = command.split()
    assert argv[:2] == ["python", "../release-controls/scripts/verify_release.py"]
    argv = [substitutions.get(arg, arg) for arg in argv[1:]]
    assert not [arg for arg in argv if "$" in arg], argv

    # Release-state and environment checks have their own coverage; this exercises real git binding.
    monkeypatch.chdir(source)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(release, "verify_metadata", lambda **kwargs: (version, {}))
    monkeypatch.setattr(release, "_load_json", lambda path: {})
    monkeypatch.setattr(release, "verify_environment_protection", lambda *args: None)
    monkeypatch.setattr(release, "DISTRIBUTIONS", release.DISTRIBUTIONS)
    monkeypatch.setattr(release, "RELEASE_BRANCH", release.RELEASE_BRANCH)
    monkeypatch.setattr(release, "ROOT", release.ROOT)
    monkeypatch.setattr(release, "RELEASE_STATE_PATH", release.RELEASE_STATE_PATH)
    status = release.main()
    stderr = capsys.readouterr().err
    if tag_state == "approved":
        assert status == 0, stderr
    else:
        assert status == 1
        expected = "unknown revision" if tag_state == "absent" else "does not resolve to the approved commit"
        assert expected in stderr, stderr

    # Without the post-publication flag the pre-publication binding refuses the existing tag.
    if tag_state == "approved":
        monkeypatch.setattr(sys, "argv", [arg for arg in argv if arg != "--tag-published"])
        assert release.main() == 1
        assert "release tag must not exist before publication" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra,message",
    [
        (["--commit", "a" * 40], "--tag-published requires --tag and --commit"),
        (["--tag", "v3.0.0"], "--tag-published requires --tag and --commit"),
        (
            ["--tag", "v3.0.0", "--commit", "a" * 40, "--publication-check", "tag"],
            "--tag-published applies only to the metadata check",
        ),
    ],
)
def test_tag_published_flag_requires_metadata_binding_inputs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], extra: list[str], message: str
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify_release.py", "--distributions", str(CONTRACT), "--tag-published", *extra],
    )
    monkeypatch.setattr(release, "_version", lambda: "3.0.0")
    monkeypatch.setattr(release, "DISTRIBUTIONS", release.DISTRIBUTIONS)
    assert release.main() == 1
    assert message in capsys.readouterr().err


def _pypi_entry(name: str, digest: str) -> dict[str, object]:
    return {
        "filename": name,
        "digests": {"sha256": digest},
        "yanked": False,
        "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
    }


@pytest.mark.parametrize("job", ["validate", "publish"])
@pytest.mark.parametrize("mutation", ["none", "missing-satellite", "yanked-satellite", "digest-satellite"])
def test_registry_keyed_pypi_readback_runs_against_the_verifier(
    tmp_path: Path, job: str, mutation: str
) -> None:
    [(_, step)] = [
        (name, step)
        for name, step in _registry_steps()
        if name == job and "--publication-check pypi" in step["run"]
    ]
    script = step["run"].split(
        "python release-controls/scripts/verify_release.py --publication-check descriptor"
    )[0]
    assert 'release_version="${RELEASE_TAG#v}"' in script
    assert '"https://pypi.org/pypi/$distribution/$release_version/json"' in script
    assert "<<'PY' > \"$RUNNER_TEMP/pypi-readback.json\"" in script

    version = "3.0.0"
    hashes = {
        name: hashlib.sha256(name.encode()).hexdigest()
        for item in TRAIN
        for name in release.distribution_names(version, item.name)
    }
    workspace, runner_temp, fixtures, shims = (tmp_path / part for part in ("ws", "rt", "fx", "bin"))
    for directory in (workspace, runner_temp, fixtures, shims):
        directory.mkdir()
    # Unrooted steps resolve the checkout from the verifier's own location, so the trusted
    # controls stub carries a real copy of the verifier beside a 3.0.0 project version.
    controls = _release_root(workspace / "release-controls", version)
    (controls / "scripts").mkdir()
    (controls / "scripts/verify_release.py").write_bytes(Path("scripts/verify_release.py").read_bytes())
    manifest = fixtures / "release-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": release.MANIFEST_SCHEMA,
                "version": version,
                "commit": REGISTRY_COMMIT,
                "workflow_sha": REGISTRY_WORKFLOW_SHA,
                "files": hashes,
            }
        ),
        encoding="utf-8",
    )
    for item in TRAIN:
        urls = [_pypi_entry(name, hashes[name]) for name in release.distribution_names(version, item.name)]
        if item.name == "mcp-audits-labs" and mutation == "yanked-satellite":
            urls[1]["yanked"] = True
        if item.name == "mcp-audits-labs" and mutation == "digest-satellite":
            urls[0]["digests"] = {"sha256": "0" * 64}
        if item.name == "mcp-audits-proof" and mutation == "missing-satellite":
            continue
        (fixtures / f"{item.name}-{version}.json").write_text(
            json.dumps({"info": {"name": item.name, "version": version}, "urls": urls}), encoding="utf-8"
        )
    (shims / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    # Offline stand-ins: curl serves fixtures by exact URL (404 -> exit 22 like --fail);
    # gh copies the manifest.
    (shims / "curl").write_text(
        "#!/bin/sh\n"
        'for arg; do case "$prev" in --output) out="$arg";; esac; prev="$arg";'
        ' case "$arg" in https://*) url="$arg";; esac; done\n'
        'echo "$url" >> "$FIXTURES/urls.log"\n'
        'name="${url#https://pypi.org/pypi/}"; name="${name%/json}"\n'
        'file="$FIXTURES/${name%/*}-${name#*/}.json"\n'
        '[ -f "$file" ] || exit 22\n'
        'cp "$file" "$out"\n',
        encoding="utf-8",
    )
    (shims / "gh").write_text(
        '#!/bin/sh\ncp "$FIXTURES/release-manifest.json" "$RUNNER_TEMP/"\n', encoding="utf-8"
    )
    for shim in shims.iterdir():
        shim.chmod(0o755)

    env = {
        "PATH": f"{shims}:/usr/bin:/bin",
        "FIXTURES": str(fixtures),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_REPOSITORY": "example/mcp-audit",
        "GH_TOKEN": "unused",
        "RELEASE_TAG": f"v{version}",
        "RELEASE_COMMIT": REGISTRY_COMMIT,
        "WORKFLOW_SHA": REGISTRY_WORKFLOW_SHA,
        "MANIFEST_SHA256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    }
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    requested = (fixtures / "urls.log").read_text(encoding="utf-8").split()
    expected_urls = [f"https://pypi.org/pypi/{item.name}/{version}/json" for item in TRAIN]
    if mutation == "missing-satellite":
        assert result.returncode != 0
        assert requested == expected_urls
        assert not (runner_temp / "pypi-readback.json").exists()
        # Even if a readback lacking the satellite were produced, the step's verifier call rejects it.
        partial = {
            item.name: json.loads((fixtures / f"{item.name}-{version}.json").read_text(encoding="utf-8"))
            for item in TRAIN[:2]
        }
        (runner_temp / "pypi-readback.json").write_text(json.dumps(partial), encoding="utf-8")
        verifier = subprocess.run(
            ["bash", "-e", "-c", script.split("\nPY\n", maxsplit=1)[1]],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert verifier.returncode != 0
        assert "PyPI readback must include every distribution" in verifier.stderr
        return
    assert requested == expected_urls
    readback = json.loads((runner_temp / "pypi-readback.json").read_text(encoding="utf-8"))
    assert list(readback) == [item.name for item in TRAIN]
    if mutation == "none":
        assert result.returncode == 0, result.stderr
        assert "publication pypi verified" in result.stdout
    else:
        assert result.returncode != 0
        expected = "yanked" if mutation == "yanked-satellite" else "do not match the approved manifest"
        assert expected in result.stderr


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
