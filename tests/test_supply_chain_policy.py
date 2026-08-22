from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
# Resolved from the named releases in each action's owning GitHub repository.
# Changing any row is an explicit supply-chain review event, not a shape-only update.
REVIEWED_ACTION_RELEASES = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "v8.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1"),
    "astral-sh/setup-uv": ("20cfd1bf945f4377ade1205e4dbc17946fc9a30d", "v10.0.1"),
    "github/codeql-action/analyze": ("5595ccaf912efad79be6eef63a5619ff05969be3", "v4.37.6"),
    "github/codeql-action/init": ("5595ccaf912efad79be6eef63a5619ff05969be3", "v4.37.6"),
    "github/codeql-action/upload-sarif": ("5595ccaf912efad79be6eef63a5619ff05969be3", "v4.37.6"),
    "google/clusterfuzzlite/actions/build_fuzzers": (
        "884713a6c30a92e5e8544c39945cd7cb630abcd1",
        "v1",
    ),
    "google/clusterfuzzlite/actions/run_fuzzers": (
        "884713a6c30a92e5e8544c39945cd7cb630abcd1",
        "v1",
    ),
    "ossf/scorecard-action": ("2d1146689b8cda280b9bc96326124645441f03bc", "v2.4.4"),
    "pypa/gh-action-pypi-publish": ("dc37677b2e1c63e2034f94d8a5b11f265b73ba33", "v1.14.2"),
    "saagpatel/agent-permission-diff-bot": (
        "20bc07d1f8052765d3a65378222a08869a7dd027",
        "v0.5.0",
    ),
}


def test_mcp_runtime_dependency_excludes_known_vulnerable_versions() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    mcp_requirement = next(
        requirement for requirement in project["dependencies"] if requirement.startswith("mcp")
    )

    match = re.fullmatch(r"mcp>=(\d+)\.(\d+)\.(\d+),<2\.0", mcp_requirement)
    assert match is not None, "mcp must retain an explicit minimum safe version"
    assert tuple(map(int, match.groups())) >= (1, 28, 1)


def test_direct_security_floors_exclude_known_vulnerable_versions() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    requirements = set(project["dependencies"])

    assert "cryptography>=50.0.0,<51.0" in requirements
    assert "click>=8.3.3,<9.0" in requirements


def test_clusterfuzzlite_uses_oss_fuzz_python_builder() -> None:
    build_script = (REPO_ROOT / ".clusterfuzzlite" / "build.sh").read_text(encoding="utf-8")
    dockerfile = (REPO_ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(encoding="utf-8")
    requirements = (REPO_ROOT / ".clusterfuzzlite" / "requirements.txt").read_text(encoding="utf-8")

    assert 'compile_python_fuzzer "$fuzzer"' in build_script
    assert "pyinstaller" not in build_script.lower()
    assert "pip install ." not in build_script
    assert "pip install --require-hashes -r .clusterfuzzlite/requirements.txt" in build_script
    assert "PYTHONPATH" in build_script
    assert "gcr.io/oss-fuzz-base/base-builder-python@sha256:" in dockerfile
    assert "--hash=sha256:" in requirements


def test_external_github_actions_are_pinned_to_immutable_commits() -> None:
    action_files = [
        REPO_ROOT / "action.yml",
        *(REPO_ROOT / ".github" / "workflows").glob("*.yml"),
        *(REPO_ROOT / ".github" / "workflows").glob("*.yaml"),
    ]

    invalid_uses: list[str] = []
    observed_actions: set[str] = set()
    for action_file in action_files:
        for line_number, line in enumerate(action_file.read_text(encoding="utf-8").splitlines(), start=1):
            match = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#\s+(\S+))?\s*$", line)
            if match is None:
                continue
            action_ref = match.group(1)
            if action_ref.startswith("./") or action_ref.startswith("docker://"):
                continue
            action, separator, revision = action_ref.rpartition("@")
            release = match.group(2)
            expected = REVIEWED_ACTION_RELEASES.get(action)
            observed_actions.add(action)
            if (
                not separator
                or FULL_COMMIT_SHA.fullmatch(revision) is None
                or release is None
                or expected != (revision, release)
            ):
                invalid_uses.append(
                    f"{action_file.relative_to(REPO_ROOT)}:{line_number}: {action_ref}"
                    f" # {release or '<missing release>'}"
                )

    assert not invalid_uses, "external actions must match reviewed release commits:\n" + "\n".join(
        invalid_uses
    )
    assert observed_actions == set(REVIEWED_ACTION_RELEASES), (
        "reviewed action policy and repository use must stay in sync"
    )
