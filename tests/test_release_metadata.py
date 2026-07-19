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
        "published_version": "2.4.0",
        "previous_version": "2.4.0",
        "status": "candidate",
    }
    assert server["version"] == state["published_version"]
    assert server["packages"][0]["version"] == state["published_version"]
    assert f"## [{version}] - Unreleased" in changelog
    assert f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/" in changelog
    assert "saagpatel/MCPAudit@v2.4.0" in readme
    assert "saagpatel/MCPAudit@v2.4.0" in adoption
    assert "rev: v2.4.0" in adoption


def test_release_version_is_a_stable_semantic_version() -> None:
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", _project_version())


def test_candidate_metadata_verifier_passes() -> None:
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
        (["--require-publishable"], "candidate state is intentionally non-publishable"),
        (["--approval-token", "wrong"], "publication approval token is invalid"),
    ],
)
def test_candidate_metadata_verifier_fails_closed(
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


def test_publication_requires_a_separate_manual_dispatch() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")

    trigger = workflow.split("\npermissions:", maxsplit=1)[0]
    assert "workflow_dispatch:" in trigger
    assert "\n  push:" not in trigger
    assert "commit:" in trigger
    assert "tag:" in trigger
    assert "approval:" in trigger


def test_oidc_authority_is_confined_to_post_build_publish_job() -> None:
    workflow = Path(".github/workflows/publish.yml").read_text(encoding="utf-8")
    build_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)

    assert "id-token: write" not in build_job
    assert "uv run pytest" in build_job
    assert "scripts/verify_release.py" in build_job
    assert "actions/upload-artifact@" in build_job
    assert "needs: build" in publish_job
    assert "environment: pypi" in publish_job
    assert "id-token: write" in publish_job
    assert "sha256sum -c SHA256SUMS" in publish_job
    assert publish_job.index("sha256sum -c SHA256SUMS") < publish_job.index("pypa/gh-action-pypi-publish@")
