"""Permission corpus precision/recall checks on explicitly labeled tool/category pairs.

Usage: uv run python tests/validation/validate_patterns.py

Positive rows require the listed categories; they are not exhaustive labels.
Rows with categories: [] require silence and count every detected category as FP.
See README.md in this directory for category gates and the known FP baseline.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NotRequired, TypedDict, cast

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import PermissionFinding, ToolAnnotations, ToolInfo

SERVERS_DIR = Path(__file__).parent / "servers"
BENIGN_PATH = Path(__file__).parent / "benign_tools.json"

_CONFIDENCE_ORDER = ["low", "medium", "high", "declared", "llm"]
MIN_RECALL = 0.8
MIN_EXPECTED_FOR_RECALL_GATE = 3
# The P2-1 calibration requires zero false positives on explicit negative rows.
MIN_PRECISION = {
    "file_read": 1.0,
    "file_write": 1.0,
    "exfiltration": 1.0,
    "network": 1.0,
    "destructive": 1.0,
    "shell_execution": 1.0,
}


class ToolFixture(TypedDict):
    name: str
    description: NotRequired[str]
    input_schema: NotRequired[dict[str, object]]


class ExpectedFinding(TypedDict):
    tool: str
    categories: list[str]
    min_confidence: NotRequired[str]


class Fixture(TypedDict):
    server_name: str
    tools: list[ToolFixture]
    expected_findings: list[ExpectedFinding]
    keyword_only: NotRequired[bool]
    tool_annotations: NotRequired[dict[str, bool]]


@dataclass
class CategoryStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        total = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / total if total else 1.0


def _confidence_meets_min(actual: str, minimum: str) -> bool:
    """Return True if actual confidence is >= minimum required."""
    try:
        return _CONFIDENCE_ORDER.index(actual.lower()) >= _CONFIDENCE_ORDER.index(minimum.lower())
    except ValueError:
        return False


def load_fixture(path: Path) -> Fixture:
    return cast(Fixture, json.loads(path.read_text()))


def load_benign_fixtures() -> list[Fixture]:
    return cast(list[Fixture], json.loads(BENIGN_PATH.read_text()))


def build_tool_infos(fixture: Fixture) -> list[ToolInfo]:
    return [
        ToolInfo(
            name=tool["name"],
            description=tool.get("description", ""),
            input_schema=tool.get("input_schema", {}),
            annotations=ToolAnnotations.model_validate(fixture["tool_annotations"])
            if "tool_annotations" in fixture
            else None,
        )
        for tool in fixture["tools"]
    ]


def score_findings(fixture: Fixture, findings: list[PermissionFinding]) -> dict[str, CategoryStats]:
    actual = {(finding.tool_name, finding.category.value): finding.confidence.value for finding in findings}
    stats: dict[str, CategoryStats] = {}
    for expected in fixture["expected_findings"]:
        name = expected["tool"]
        categories = expected["categories"]
        if not categories:
            for tool_name, category in actual:
                if tool_name == name:
                    stats.setdefault(category, CategoryStats()).fp += 1
            continue
        for category in categories:
            counts = stats.setdefault(category, CategoryStats())
            confidence = actual.get((name, category))
            if confidence is not None and _confidence_meets_min(
                confidence, expected.get("min_confidence", "low")
            ):
                counts.tp += 1
            else:
                counts.fn += 1
    return stats


def evaluate_fixture(fixture: Fixture) -> dict[str, CategoryStats]:
    analyzer = PermissionAnalyzer()
    tools = build_tool_infos(fixture)
    if fixture.get("keyword_only", False):
        findings = [finding for tool in tools for finding in analyzer.analyze_tool_keywords(tool)]
    else:
        findings = analyzer.analyze_server(tools)
    return score_findings(fixture, findings)


def failed_metrics(stats: dict[str, CategoryStats]) -> list[str]:
    failures = []
    for category, counts in sorted(stats.items()):
        if counts.precision < MIN_PRECISION.get(category, 1.0):
            failures.append(f"{category} precision {counts.precision:.1%}")
        if counts.tp + counts.fn >= MIN_EXPECTED_FOR_RECALL_GATE and counts.recall < MIN_RECALL:
            failures.append(f"{category} recall {counts.recall:.1%}")
    return failures


def run_validation(fixtures: list[Fixture] | None = None) -> int:
    if fixtures is None:
        paths = sorted(SERVERS_DIR.glob("*.json"))
        if not paths:
            print("No fixture files found in", SERVERS_DIR)
            return 1
        fixtures = [load_fixture(path) for path in paths] + load_benign_fixtures()

    if not fixtures:
        print("No fixtures supplied")
        return 1

    stats: dict[str, CategoryStats] = {}
    print("\n=== Per-Server Results ===")
    print(f"{'Server':<40} {'Tools':>5} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("-" * 65)
    for fixture in fixtures:
        server_stats = evaluate_fixture(fixture)
        for category, counts in server_stats.items():
            totals = stats.setdefault(category, CategoryStats())
            totals.tp += counts.tp
            totals.fp += counts.fp
            totals.fn += counts.fn
        tp = sum(counts.tp for counts in server_stats.values())
        fp = sum(counts.fp for counts in server_stats.values())
        fn = sum(counts.fn for counts in server_stats.values())
        print(f"{fixture['server_name']:<40} {len(fixture['tools']):>5} {tp:>4} {fp:>4} {fn:>4}")

    print("\n=== Per-Category Metrics (explicit labels only) ===")
    print(f"{'Category':<20} {'TP':>4} {'FP':>4} {'FN':>4} {'Precision':>10} {'Recall':>8} {'F1':>8}  Status")
    print("-" * 85)
    for category, counts in sorted(stats.items()):
        status = "FAIL" if failed_metrics({category: counts}) else "OK"
        print(
            f"{category:<20} {counts.tp:>4} {counts.fp:>4} {counts.fn:>4} "
            f"{counts.precision:>10.1%} {counts.recall:>8.1%} {counts.f1:>8.1%}  {status}"
        )

    failures = failed_metrics(stats)
    if failures:
        print(f"\nFAILED: {', '.join(failures)}")
        return 1

    total = CategoryStats(
        tp=sum(counts.tp for counts in stats.values()),
        fp=sum(counts.fp for counts in stats.values()),
        fn=sum(counts.fn for counts in stats.values()),
    )
    print(
        f"\nPASSED: Overall precision {total.precision:.1%}, recall {total.recall:.1%}, "
        f"F1 {total.f1:.1%} ({total.tp} TP, {total.fp} FP, {total.fn} FN)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run_validation())
