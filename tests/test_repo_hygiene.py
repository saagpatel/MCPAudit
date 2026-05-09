"""Repository hygiene checks for files that can drift silently on macOS."""

from __future__ import annotations

import subprocess


def test_github_paths_have_no_case_conflicts() -> None:
    result = subprocess.run(
        ["git", "ls-files", ".github"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    lowered = [path.lower() for path in paths]

    assert len(lowered) == len(set(lowered))
