"""Release metadata must distinguish a candidate from a published release."""

from __future__ import annotations

import json
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
    assert observed == [{"tag": None, "commit": "a" * 40, "require_landed": True}]


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
    assert "tag:" in trigger
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
    assert "environment: pypi" in publish_job
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
    assert 'test ! -e "$smoke/bin/proof-before-action"' in build_job
    assert "proof-before-action, version $release_version" not in build_job
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
    assert validate_job.count('"https://pypi.org/pypi/$distribution/$release_version/json"') == 1
    assert publish_job.count('"https://pypi.org/pypi/$distribution/$release_version/json"') == 1
    assert validate_job.count("for distribution in $(python -c") == 1
    assert publish_job.count("for distribution in $(python -c") == 1
    assert 'item["name"]: json.loads' in validate_job
    assert 'item["name"]: json.loads' in publish_job
    assert validate_job.count("--distributions release-controls/release/distributions.json") == 1
    assert publish_job.count("--distributions release-controls/release/distributions.json") == 1
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
