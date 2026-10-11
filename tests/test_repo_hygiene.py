"""Repository hygiene checks for files that can drift silently on macOS."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path


def _short_wall_clock_assertions(source: str) -> list[int]:
    tree = ast.parse(source)
    violations: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        for comparison in ast.walk(node.test):
            if not isinstance(comparison, ast.Compare):
                continue
            operands = [comparison.left, *comparison.comparators]
            for operator, left, right in zip(comparison.ops, operands[:-1], operands[1:], strict=True):
                if isinstance(operator, (ast.Lt, ast.LtE)):
                    threshold, measured = right, left
                elif isinstance(operator, (ast.Gt, ast.GtE)):
                    threshold, measured = left, right
                else:
                    continue
                expression = ast.unparse(measured)
                has_clock_marker = any(
                    marker in expression
                    for marker in (
                        "perf_counter",
                        "monotonic",
                        "elapsed",
                        "duration",
                        "latency",
                        "wall",
                        "seconds",
                    )
                )
                if (
                    has_clock_marker
                    and isinstance(threshold, ast.Constant)
                    and isinstance(threshold.value, (int, float))
                    and threshold.value < 2
                ):
                    violations.append(node.lineno)
                    break
    return violations


def test_short_wall_clock_assertion_lint_detects_and_allows_expected_cases() -> None:
    assert _short_wall_clock_assertions("assert elapsed < 1.5") == [1]
    assert _short_wall_clock_assertions("assert time.perf_counter() - start <= 1") == [1]
    assert _short_wall_clock_assertions("assert 1 > elapsed") == [1]
    assert _short_wall_clock_assertions("assert elapsed > 0") == []
    assert _short_wall_clock_assertions('assert number(metrics, "wall_seconds") < 1') == [1]
    assert _short_wall_clock_assertions("assert elapsed < 2") == []
    assert _short_wall_clock_assertions("assert elapsed < 10 * small + 0.05") == []
    assert _short_wall_clock_assertions("assert count < 1") == []


def test_tests_have_no_sub_two_second_wall_clock_assertions() -> None:
    violations = {
        str(path): _short_wall_clock_assertions(path.read_text(encoding="utf-8"))
        for path in Path("tests").rglob("*.py")
    }
    violations = {path: lines for path, lines in violations.items() if lines}
    assert not violations, f"sub-2-second wall-clock assertions: {violations}"


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
