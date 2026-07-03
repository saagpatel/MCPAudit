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


def test_no_tracked_files_match_gitignore() -> None:
    """A gitignored path being tracked means internal material regressed into
    the public repo (launch-posts.md did this once already)."""
    result = subprocess.run(
        ["git", "ls-files", "-i", "-c", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    )
    tracked_ignored = [line for line in result.stdout.splitlines() if line]
    assert tracked_ignored == [], f"gitignored files are tracked: {tracked_ignored}"


def test_output_contract_documents_every_sarif_rule_id() -> None:
    """README promises docs/OUTPUT-CONTRACT.md documents all SARIF rule IDs;
    a consumer building an MCP0xx triage table from the doc silently drops
    findings for any undocumented ID (MCP040-042 shipped undocumented once)."""
    import re
    from pathlib import Path

    source_ids: set[int] = set()
    for name in ("sarif.py", "taxonomy.py"):
        text = Path("src/mcp_audit", name).read_text()
        source_ids |= {int(m) for m in re.findall(r'"MCP0(\d\d)"', text)}
    assert source_ids, "expected to find SARIF rule IDs in source"

    doc = Path("docs/OUTPUT-CONTRACT.md").read_text()
    documented: set[int] = set()
    for start, end in re.findall(r"MCP0(\d\d)`-`MCP0(\d\d)", doc):
        documented |= set(range(int(start), int(end) + 1))
    documented |= {int(m) for m in re.findall(r"MCP0(\d\d)", doc)}

    missing = source_ids - documented
    assert not missing, f"SARIF rule IDs undocumented in OUTPUT-CONTRACT.md: {sorted(missing)}"
