from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def test_mcp_runtime_dependency_excludes_known_vulnerable_versions() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    mcp_requirement = next(
        requirement for requirement in project["dependencies"] if requirement.startswith("mcp")
    )

    match = re.fullmatch(r"mcp>=(\d+)\.(\d+)\.(\d+)", mcp_requirement)
    assert match is not None, "mcp must retain an explicit minimum safe version"
    assert tuple(map(int, match.groups())) >= (1, 28, 1)


def test_external_github_actions_are_pinned_to_immutable_commits() -> None:
    action_files = [
        REPO_ROOT / "action.yml",
        *(REPO_ROOT / ".github" / "workflows").glob("*.yml"),
        *(REPO_ROOT / ".github" / "workflows").glob("*.yaml"),
    ]

    mutable_uses: list[str] = []
    for action_file in action_files:
        for line_number, line in enumerate(action_file.read_text(encoding="utf-8").splitlines(), start=1):
            match = re.match(r"\s*uses:\s*(\S+)", line)
            if match is None:
                continue
            action_ref = match.group(1)
            if action_ref.startswith("./") or action_ref.startswith("docker://"):
                continue
            _, separator, revision = action_ref.rpartition("@")
            if not separator or FULL_COMMIT_SHA.fullmatch(revision) is None:
                mutable_uses.append(f"{action_file.relative_to(REPO_ROOT)}:{line_number}: {action_ref}")

    assert not mutable_uses, "external actions must use immutable commit SHAs:\n" + "\n".join(mutable_uses)
