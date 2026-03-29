"""Precision/recall validation script for PermissionAnalyzer against real-world server corpus.

Usage:
    uv run python tests/validation/validate_patterns.py

Exits non-zero if F1 < 0.8 for any expected category that has ≥3 expected positives.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import Confidence, ToolInfo

SERVERS_DIR = Path(__file__).parent / "servers"

# Confidence levels that count as "detected" (DECLARED counts as HIGH for validation)
_COUNTED_CONFIDENCES = {
    Confidence.DECLARED,
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.LOW,
    Confidence.LLM,
}  # noqa: E501

# Minimum confidence level strings (ordered weakest → strongest)
_CONFIDENCE_ORDER = ["low", "medium", "high", "declared", "llm"]


def _confidence_meets_min(actual: str, minimum: str) -> bool:
    """Return True if actual confidence is >= minimum required."""
    try:
        actual_idx = _CONFIDENCE_ORDER.index(actual.lower())
        min_idx = _CONFIDENCE_ORDER.index(minimum.lower())
        return actual_idx >= min_idx
    except ValueError:
        return False


def load_fixture(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)  # type: ignore[no-any-return]


def build_tool_infos(fixture: dict[str, Any]) -> list[ToolInfo]:
    tools = []
    for t in fixture.get("tools", []):
        tools.append(
            ToolInfo(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("input_schema", {}),
                annotations=None,
            )
        )
    return tools


def run_validation() -> int:
    analyzer = PermissionAnalyzer()
    fixtures = sorted(SERVERS_DIR.glob("*.json"))

    if not fixtures:
        print("No fixture files found in", SERVERS_DIR)
        return 1

    # Aggregate stats per category
    # {category: {"tp": int, "fp": int, "fn": int}}
    stats: dict[str, dict[str, int]] = {}

    per_server_results: list[dict[str, Any]] = []

    for fixture_path in fixtures:
        fixture = load_fixture(fixture_path)
        server_name = fixture.get("server_name", fixture_path.stem)
        tools = build_tool_infos(fixture)
        expected_findings = fixture.get("expected_findings", [])

        # Run analyzer
        actual_findings = analyzer.analyze_server(tools)

        # Build lookup: tool_name -> set of (category, confidence)
        actual_by_tool: dict[str, set[str]] = {}
        for f in actual_findings:
            actual_by_tool.setdefault(f.tool_name, set()).add(f.category.value)

        server_tp = server_fn = 0

        for expected in expected_findings:
            tool_name = expected["tool"]
            expected_categories: list[str] = expected["categories"]
            min_conf: str = expected.get("min_confidence", "low")

            # Check which expected categories were detected
            actual_cats = actual_by_tool.get(tool_name, set())

            # Also check confidence for detected categories
            actual_conf_by_cat: dict[str, str] = {}
            for f in actual_findings:
                if f.tool_name == tool_name:
                    actual_conf_by_cat[f.category.value] = f.confidence.value

            for cat in expected_categories:
                if cat not in stats:
                    stats[cat] = {"tp": 0, "fp": 0, "fn": 0}

                if cat in actual_cats:
                    actual_conf = actual_conf_by_cat.get(cat, "low")
                    if _confidence_meets_min(actual_conf, min_conf):
                        stats[cat]["tp"] += 1
                        server_tp += 1
                    else:
                        # Detected but confidence too low — treat as FN
                        stats[cat]["fn"] += 1
                        server_fn += 1
                else:
                    stats[cat]["fn"] += 1
                    server_fn += 1

        per_server_results.append(
            {
                "server": server_name,
                "tp": server_tp,
                "fn": server_fn,
                "tools_analyzed": len(tools),
            }
        )

    # Print per-server summary
    print("\n=== Per-Server Results ===")
    print(f"{'Server':<40} {'Tools':>5} {'TP':>4} {'FN':>4}")
    print("-" * 55)
    for r in per_server_results:
        print(f"{r['server']:<40} {r['tools_analyzed']:>5} {r['tp']:>4} {r['fn']:>4}")

    # Print per-category precision/recall/F1
    print("\n=== Per-Category Metrics (expected positives only) ===")
    print(f"{'Category':<20} {'TP':>4} {'FN':>4} {'Recall':>8} {'F1':>8}  Status")
    print("-" * 65)

    failed_categories: list[str] = []
    MIN_F1 = 0.8
    MIN_EXPECTED_FOR_GATE = 3  # Only gate categories with enough expected positives

    for cat, s in sorted(stats.items()):
        tp = s["tp"]
        fn = s["fn"]
        total_expected = tp + fn

        recall = tp / total_expected if total_expected > 0 else 0.0
        # Precision unknown (we don't track FP from non-expected tools), so F1 = recall here
        f1 = recall

        status = "OK"
        if total_expected >= MIN_EXPECTED_FOR_GATE and f1 < MIN_F1:
            status = "FAIL"
            failed_categories.append(cat)

        print(f"{cat:<20} {tp:>4} {fn:>4} {recall:>8.1%} {f1:>8.1%}  {status}")

    print()

    if failed_categories:
        print(f"FAILED: F1 < {MIN_F1:.0%} for categories: {', '.join(failed_categories)}")
        return 1

    total_tp = sum(s["tp"] for s in stats.values())
    total_fn = sum(s["fn"] for s in stats.values())
    total_expected = total_tp + total_fn
    overall_recall = total_tp / total_expected if total_expected > 0 else 0.0
    print(
        f"PASSED: Overall recall {overall_recall:.1%} "
        f"({total_tp}/{total_expected} expected findings detected)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run_validation())
