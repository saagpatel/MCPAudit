"""Regression checks for labeled permissions and benign keyword inference."""

from __future__ import annotations

import pytest

from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding
from tests.validation.validate_patterns import (
    SERVERS_DIR,
    CategoryStats,
    Fixture,
    evaluate_fixture,
    failed_metrics,
    load_benign_fixtures,
    load_fixture,
    run_validation,
    score_findings,
)

SERVER_FIXTURES = [load_fixture(path) for path in sorted(SERVERS_DIR.glob("*.json"))]
BENIGN_FIXTURES = load_benign_fixtures()


@pytest.mark.parametrize("fixture", SERVER_FIXTURES, ids=lambda fixture: fixture["server_name"])
def test_server_validation_fixture(fixture: Fixture) -> None:
    failures = failed_metrics(evaluate_fixture(fixture))
    assert not failures, f"{fixture['server_name']}: {failures}"


@pytest.mark.parametrize(
    "fixture",
    BENIGN_FIXTURES,
    ids=lambda fixture: fixture["server_name"],
)
def test_benign_validation_fixture(fixture: Fixture) -> None:
    stats = evaluate_fixture(fixture)
    assert sum(counts.fp for counts in stats.values()) == 0, f"{fixture['server_name']}: {stats}"


def test_validation_reports_raw_precision_recall_and_f1(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_validation() == 0
    output = capsys.readouterr().out
    assert "Precision" in output and "Recall" in output and "F1" in output
    assert "117 TP, 0 FP, 1 FN" in output
    assert "benign-export-csv" in output
    assert "100.0%" in output


def test_silent_row_counts_distinct_categories_even_at_low_confidence() -> None:
    fixture: Fixture = {
        "server_name": "synthetic-negative",
        "tools": [{"name": "calculate"}],
        "expected_findings": [{"tool": "calculate", "categories": []}],
    }
    finding = PermissionFinding(
        tool_name="calculate",
        category=PermissionCategory.EXFILTRATION,
        confidence=Confidence.LOW,
        evidence=["synthetic"],
    )
    stats = score_findings(fixture, [finding, finding])
    assert stats == {"exfiltration": CategoryStats(fp=1)}
    assert stats["exfiltration"].precision == 0.0
    assert failed_metrics(stats) == ["exfiltration precision 0.0%"]


def test_insufficient_confidence_is_false_negative() -> None:
    fixture: Fixture = {
        "server_name": "synthetic-positive",
        "tools": [{"name": "read_file"}],
        "expected_findings": [{"tool": "read_file", "categories": ["file_read"], "min_confidence": "high"}],
    }
    finding = PermissionFinding(
        tool_name="read_file",
        category=PermissionCategory.FILE_READ,
        confidence=Confidence.LOW,
        evidence=["synthetic"],
    )
    assert score_findings(fixture, [finding]) == {"file_read": CategoryStats(fn=1)}


@pytest.mark.parametrize(
    ("category", "tp", "fp"),
    [
        ("file_read", 19, 0),
        ("file_write", 30, 0),
        ("exfiltration", 5, 0),
        ("network", 49, 0),
        ("destructive", 10, 0),
        ("shell_execution", 4, 0),
    ],
)
def test_category_precision_gate_rejects_one_additional_fp(category: str, tp: int, fp: int) -> None:
    assert failed_metrics({category: CategoryStats(tp=tp, fp=fp)}) == []
    failures = failed_metrics({category: CategoryStats(tp=tp, fp=fp + 1)})
    assert len(failures) == 1 and "precision" in failures[0]


@pytest.mark.parametrize(("tp", "fn", "passes"), [(4, 1, True), (3, 2, False), (0, 2, True)])
def test_recall_gate_preserves_threshold_and_minimum_support(tp: int, fn: int, passes: bool) -> None:
    assert (not failed_metrics({"network": CategoryStats(tp=tp, fn=fn)})) is passes


def test_f1_uses_both_false_positives_and_false_negatives() -> None:
    counts = CategoryStats(tp=3, fp=1, fn=2)
    assert counts.precision == 0.75
    assert counts.recall == 0.6
    assert counts.f1 == pytest.approx(2 / 3)


def test_validation_fails_on_false_positive_without_expected_positives(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture: Fixture = {
        "server_name": "synthetic-upload",
        "keyword_only": True,
        "tools": [{"name": "upload"}],
        "expected_findings": [{"tool": "upload", "categories": []}],
    }
    assert run_validation([fixture]) == 1
    output = capsys.readouterr().out
    assert "synthetic-upload" in output
    assert "FAILED: exfiltration precision 0.0%" in output
