#!/usr/bin/env python3
"""Launch preflight checks for the MCPAudit public launch packet."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

REPO = "saagpatel/MCPAudit"
PACKAGE_NAME = "mcp-audits"
COMMAND_NAME = "mcp-audit"
EXPECTED_WORKFLOWS = {"CI", "Self Audit", "CodeQL"}
TITLE = "Show HN: mcp-audit \u2013 see what your MCP servers can actually touch"
REPO_URL = "https://github.com/saagpatel/MCPAudit"
HN_SUBMIT_PAGE_URL = "https://news.ycombinator.com/submit"
FIELD_REPORT_COMMAND = "mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact"
FIELD_REPORT_ISSUE = "https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
PYPI_PROJECT_URL = f"https://pypi.org/project/{PACKAGE_NAME}/"
PYPI_SIMPLE_URL = f"https://pypi.org/simple/{PACKAGE_NAME}/"
PUBLIC_URLS = {
    "GitHub README": "https://github.com/saagpatel/MCPAudit#readme",
    "PyPI project": PYPI_PROJECT_URL,
    "field-report issue template": FIELD_REPORT_ISSUE,
    "field-report request": (
        "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md"
    ),
    "hero GIF": "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/assets/hero-scan.gif",
    "config-only preview": (
        "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/assets/mcp-audit-config-only-scan.png"
    ),
    "SARIF proof": "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/assets/ci-sarif.png",
    "policy gate GIF": "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/assets/policy-gate.gif",
    "HTML report preview": "https://raw.githubusercontent.com/saagpatel/MCPAudit/main/docs/assets/html-report.png",
}

REQUIRED_TEXT = {
    Path("docs/LAUNCH-CONTROL-CARD.md"): [
        "Tuesday, June 23, 2026",
        "Wednesday, June 24, 2026",
        "Do not launch on a weekend",
        HN_SUBMIT_PAGE_URL,
        REPO_URL,
        TITLE,
        FIELD_REPORT_COMMAND,
        "SECURITY.md",
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
    parser.add_argument("--skip-public", action="store_true", help="Skip public GitHub URL checks.")
    parser.add_argument("--skip-package", action="store_true", help="Skip PyPI and uvx package checks.")
    parser.add_argument("--print-hn-copy", action="store_true", help="Print the exact HN submit fields.")
    args = parser.parse_args()

    failures: list[str] = []
    _check_docs(failures)
    _check_assets(failures)
    hn_comment = _check_hn_copy(failures)

    if not args.skip_git:
        _check_git(failures)
    if not args.skip_remote:
        _check_remote(failures)
    if not args.skip_public:
        _check_public_urls(failures)
    package_version: str | None = None
    if not args.skip_package:
        package_version = _check_package(failures)

    if failures:
        print("Launch preflight failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Launch preflight passed.")
    print(f"- title chars: {len(TITLE)}")
    print(f"- HN submit page: {HN_SUBMIT_PAGE_URL} (login/auth not checked)")
    print(f"- repo URL: {REPO_URL}")
    print(f"- field report command: {FIELD_REPORT_COMMAND}")
    if not args.skip_public:
        print(f"- public URLs checked: {len(PUBLIC_URLS)}")
    if package_version is not None:
        print(f"- PyPI package version: {package_version}")
    if args.print_hn_copy and hn_comment is not None:
        _print_hn_copy(hn_comment)
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


def _check_hn_copy(failures: list[str]) -> str | None:
    try:
        comment = _extract_first_comment(Path("launch-posts.md"))
    except FileNotFoundError:
        return None  # optional pre-submit artifact; absence is not a blocking failure
    except ValueError as exc:
        failures.append(str(exc))
        return None

    required = [
        REPO_URL,
        FIELD_REPORT_COMMAND,
        FIELD_REPORT_ISSUE,
        "Happy to answer anything about the heuristics",
    ]
    for snippet in required:
        if snippet not in comment:
            failures.append(f"Show HN first comment is missing expected text: {snippet}")

    if " is beta" in comment.lower():
        failures.append("Show HN first comment appears to contain an affirmative beta claim.")

    return comment


def _extract_first_comment(path: Path) -> str:
    text = path.read_text()
    marker = "**Body / first comment:**"
    marker_index = text.find(marker)
    if marker_index == -1:
        raise ValueError(f"{path} is missing the Show HN first-comment marker.")

    block_start = text.find("```text", marker_index)
    if block_start == -1:
        raise ValueError(f"{path} is missing the Show HN first-comment text block.")
    content_start = text.find("\n", block_start)
    if content_start == -1:
        raise ValueError(f"{path} has a malformed Show HN first-comment text block.")

    block_end = text.find("```", content_start + 1)
    if block_end == -1:
        raise ValueError(f"{path} has an unterminated Show HN first-comment text block.")

    comment = text[content_start + 1 : block_end].strip()
    if not comment:
        raise ValueError(f"{path} has an empty Show HN first-comment text block.")
    return comment


def _print_hn_copy(comment: str) -> None:
    print()
    print("HN SUBMIT PAGE")
    print(HN_SUBMIT_PAGE_URL)
    print()
    print("HN SUBMIT URL")
    print(REPO_URL)
    print()
    print("HN TITLE")
    print(TITLE)
    print()
    print("HN FIRST COMMENT")
    print(comment)


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


def _check_public_urls(failures: list[str]) -> None:
    for label, url in PUBLIC_URLS.items():
        request = urllib.request.Request(url, headers={"User-Agent": "MCPAudit-launch-preflight/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status = response.status
                response.read(1)
        except urllib.error.HTTPError as exc:
            failures.append(f"{label} returned HTTP {exc.code}: {url}")
            continue
        except urllib.error.URLError as exc:
            failures.append(f"{label} could not be reached: {exc.reason}")
            continue
        except TimeoutError:
            failures.append(f"{label} timed out: {url}")
            continue

        if status >= 400:
            failures.append(f"{label} returned HTTP {status}: {url}")


def _check_package(failures: list[str]) -> str | None:
    expected_version = _project_version(failures)
    if expected_version is None:
        return None

    pypi_json = _fetch_json(PYPI_JSON_URL, failures, "PyPI JSON")
    if isinstance(pypi_json, dict):
        latest_version = _nested_string(pypi_json, "info", "version")
        if latest_version != expected_version:
            failures.append(f"PyPI latest is {latest_version!r}; expected {expected_version!r}.")

        releases = pypi_json.get("releases")
        if not isinstance(releases, dict) or expected_version not in releases:
            failures.append(f"PyPI JSON is missing release files for {expected_version}.")
        elif not releases[expected_version]:
            failures.append(f"PyPI JSON release {expected_version} has no files.")

        description = _nested_string(pypi_json, "info", "description") or ""
        if FIELD_REPORT_COMMAND not in description:
            failures.append("PyPI long description is missing the redacted field-report command.")

    simple = _fetch_text(PYPI_SIMPLE_URL, failures, "PyPI simple index")
    if simple is not None:
        normalized_file_prefix = PACKAGE_NAME.replace("-", "_")
        if f"{normalized_file_prefix}-{expected_version}" not in simple:
            failures.append(f"PyPI simple index is missing {normalized_file_prefix}-{expected_version}.")

    _check_uvx(expected_version, failures)
    return expected_version


def _project_version(failures: list[str]) -> str | None:
    pyproject = Path("pyproject.toml")
    try:
        parsed = tomllib.loads(pyproject.read_text())
    except OSError as exc:
        failures.append(f"could not read {pyproject}: {exc}")
        return None
    except tomllib.TOMLDecodeError as exc:
        failures.append(f"could not parse {pyproject}: {exc}")
        return None

    project = parsed.get("project")
    if not isinstance(project, dict):
        failures.append("pyproject.toml is missing [project].")
        return None

    version = project.get("version")
    if not isinstance(version, str):
        failures.append("pyproject.toml is missing project.version.")
        return None
    return version


def _check_uvx(expected_version: str, failures: list[str]) -> None:
    if shutil.which("uvx") is None:
        failures.append("uvx is not available for package smoke check.")
        return

    result = _run(
        [
            "uvx",
            "--refresh-package",
            PACKAGE_NAME,
            "--from",
            f"{PACKAGE_NAME}=={expected_version}",
            COMMAND_NAME,
            "--version",
        ]
    )
    if result.returncode != 0:
        failures.append(f"uvx package smoke failed: {result.stderr.strip() or result.stdout.strip()}")
        return

    expected_output = f"{COMMAND_NAME}, version {expected_version}"
    if expected_output not in result.stdout:
        failures.append(f"uvx reported {result.stdout.strip()!r}; expected {expected_output!r}.")


def _fetch_json(url: str, failures: list[str], label: str) -> object | None:
    text = _fetch_text(url, failures, label)
    if text is None:
        return None
    try:
        parsed: object = json.loads(text)
        return parsed
    except json.JSONDecodeError as exc:
        failures.append(f"{label} did not return valid JSON: {exc}")
        return None


def _fetch_text(url: str, failures: list[str], label: str) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": "MCPAudit-launch-preflight/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status >= 400:
                failures.append(f"{label} returned HTTP {response.status}: {url}")
                return None
            raw = response.read()
            if not isinstance(raw, bytes):
                failures.append(f"{label} returned non-bytes response data: {url}")
                return None
            return raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        failures.append(f"{label} returned HTTP {exc.code}: {url}")
    except urllib.error.URLError as exc:
        failures.append(f"{label} could not be reached: {exc.reason}")
    except TimeoutError:
        failures.append(f"{label} timed out: {url}")
    return None


def _nested_string(value: object, *keys: str) -> str | None:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, str) else None


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


if __name__ == "__main__":
    sys.exit(main())
