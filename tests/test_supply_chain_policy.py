from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
# Resolved from the named releases in each action's owning GitHub repository.
# Changing any row is an explicit supply-chain review event, not a shape-only update.
REVIEWED_ACTION_RELEASES = {
    "actions/checkout": ("9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "v7.0.0"),
    "actions/setup-python": ("ece7cb06caefa5fff74198d8649806c4678c61a1", "v6.3.0"),
    "astral-sh/setup-uv": ("37802adc94f370d6bfd71619e3f0bf239e1f3b78", "v7.6.0"),
    "github/codeql-action/analyze": ("7188fc363630916deb702c7fdcf4e481b751f97a", "v4.37.1"),
    "github/codeql-action/init": ("7188fc363630916deb702c7fdcf4e481b751f97a", "v4.37.1"),
    "github/codeql-action/upload-sarif": ("7188fc363630916deb702c7fdcf4e481b751f97a", "v4.37.1"),
    "ossf/scorecard-action": ("4eaacf0543bb3f2c246792bd56e8cdeffafb205a", "v2.4.3"),
    "pypa/gh-action-pypi-publish": ("ba38be9e461d3875417946c167d0b5f3d385a247", "v1.14.1"),
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

    match = re.fullmatch(r"mcp>=(\d+)\.(\d+)\.(\d+)", mcp_requirement)
    assert match is not None, "mcp must retain an explicit minimum safe version"
    assert tuple(map(int, match.groups())) >= (1, 28, 1)


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
