#!/usr/bin/env python3
"""Launch preflight checks for the MCPAudit public launch packet."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = "saagpatel/MCPAudit"
EXPECTED_WORKFLOWS = {"CI", "Self Audit", "CodeQL"}
TITLE = "Show HN: mcp-audit \u2013 see what your MCP servers can actually touch"
REPO_URL = "https://github.com/saagpatel/MCPAudit"
FIELD_REPORT_COMMAND = "mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact"
FIELD_REPORT_ISSUE = "https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md"

REQUIRED_TEXT = {
    Path("docs/LAUNCH-CONTROL-CARD.md"): [
        "Tuesday, June 9, 2026",
        "Wednesday, June 10, 2026",
        REPO_URL,
        TITLE,
        FIELD_REPORT_COMMAND,
        "SECURITY.md",
    ],
    Path("launch-posts.md"): [
        TITLE,
        REPO_URL,
        FIELD_REPORT_COMMAND,
        FIELD_REPORT_ISSUE,
        'before I put a "beta" label',
    ],
    Path("docs/LAUNCH-RESPONSE-PLAYBOOK.md"): [
        FIELD_REPORT_COMMAND,
        FIELD_REPORT_ISSUE,
        "SECURITY.md",
        "Not yet",
    ],
}

REQUIRED_ASSETS = [
    Path("docs/assets/hero-scan.gif"),
    Path("docs/assets/mcp-audit-config-only-scan.png"),
    Path("docs/assets/ci-sarif.png"),
    Path("docs/assets/policy-gate.gif"),
    Path("docs/assets/html-report.png"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify MCPAudit launch packet readiness.")
    parser.add_argument("--skip-git", action="store_true", help="Skip local git cleanliness checks.")
    parser.add_argument("--skip-remote", action="store_true", help="Skip GitHub Actions status checks.")
    args = parser.parse_args()

    failures: list[str] = []
    _check_docs(failures)
    _check_assets(failures)

    if not args.skip_git:
        _check_git(failures)
    if not args.skip_remote:
        _check_remote(failures)

    if failures:
        print("Launch preflight failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Launch preflight passed.")
    print(f"- title chars: {len(TITLE)}")
    print(f"- repo URL: {REPO_URL}")
    print(f"- field report command: {FIELD_REPORT_COMMAND}")
    return 0


def _check_docs(failures: list[str]) -> None:
    if len(TITLE) > 80:
        failures.append(f"Show HN title is {len(TITLE)} chars; HN limit is 80.")

    for path, snippets in REQUIRED_TEXT.items():
        if not path.exists():
            failures.append(f"missing required launch doc: {path}")
            continue
        text = path.read_text()
        for snippet in snippets:
            if snippet not in text:
                failures.append(f"{path} is missing expected text: {snippet}")

    launch_posts = Path("launch-posts.md")
    if launch_posts.exists():
        text = launch_posts.read_text().lower()
        if " is beta" in text:
            failures.append("launch-posts.md appears to contain an affirmative beta claim.")


def _check_assets(failures: list[str]) -> None:
    for path in REQUIRED_ASSETS:
        if not path.exists():
            failures.append(f"missing launch asset: {path}")
            continue
        if path.stat().st_size == 0:
            failures.append(f"empty launch asset: {path}")


def _check_git(failures: list[str]) -> None:
    status = _run(["git", "status", "--short", "--branch"])
    if status.returncode != 0:
        failures.append(f"git status failed: {status.stderr.strip()}")
        return

    lines = status.stdout.splitlines()
    if not lines or lines[0].strip() != "## main...origin/main":
        failures.append("git branch is not cleanly aligned as 'main...origin/main'.")

    dirty_lines = [line for line in lines[1:] if line.strip()]
    if dirty_lines:
        failures.append("working tree is not clean.")


def _check_remote(failures: list[str]) -> None:
    if shutil.which("gh") is None:
        failures.append("gh CLI is not available for remote check.")
        return

    head = _run(["git", "rev-parse", "HEAD"])
    if head.returncode != 0:
        failures.append(f"git rev-parse failed: {head.stderr.strip()}")
        return
    head_sha = head.stdout.strip()

    runs = _run(
        [
            "gh",
            "run",
            "list",
            "--repo",
            REPO,
            "--branch",
            "main",
            "--limit",
            "10",
            "--json",
            "headSha,status,conclusion,workflowName",
        ]
    )
    if runs.returncode != 0:
        failures.append(f"gh run list failed: {runs.stderr.strip()}")
        return

    try:
        parsed = json.loads(runs.stdout)
    except json.JSONDecodeError as exc:
        failures.append(f"could not parse gh run list JSON: {exc}")
        return

    current = [run for run in parsed if run.get("headSha") == head_sha]
    seen = {run.get("workflowName"): run for run in current}
    missing = EXPECTED_WORKFLOWS - set(seen)
    if missing:
        failures.append(f"missing current-head workflow result(s): {', '.join(sorted(missing))}")

    for workflow in sorted(EXPECTED_WORKFLOWS & set(seen)):
        run = seen[workflow]
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            failures.append(f"{workflow} is {run.get('status')}/{run.get('conclusion')} on current head.")


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


if __name__ == "__main__":
    sys.exit(main())
