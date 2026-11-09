import json
from pathlib import Path

import pytest

from redteam.range.report.report import build_report


@pytest.mark.parametrize("previous", ["CAUGHT", "MISSED"])
def test_report_renders_tables_and_flags_not_run_regression(tmp_path: Path, previous: str) -> None:
    results = tmp_path / "results.json"
    baseline = tmp_path / "baseline.json"
    report_html = tmp_path / "report.html"
    twin = {
        "id": "twin-01",
        "category": "schema <unsafe>",
        "detector": "injection",
        "expected_ids": ["MCP001"],
        "allowed_collateral": ["MCP002"],
        "emitted_ids": [],
        "predicted": "catch",
        "statuses": {"injection": {"state": "disabled", "reason": "disabled by caller"}},
        "provenance": ["MOCKED"],
        "unexpected_ids": [],
        "reason": "disabled by caller",
    }
    results.write_text(json.dumps({"twins": [twin]}), encoding="utf-8")
    baseline.write_text(
        json.dumps(
            {"twins": [{**twin, "result": previous, "statuses": {"injection": {"state": "completed"}}}]}
        ),
        encoding="utf-8",
    )

    report, exit_code = build_report(results, baseline, report_html)

    assert exit_code == 1
    assert f"twin-01: {previous} → NOT_RUN" in report
    assert "schema <unsafe>" in report
    html_output = report_html.read_text(encoding="utf-8")
    assert "<table>" in html_output
    assert "&lt;unsafe&gt;" in html_output
    assert "MOCKED" in html_output


def test_accept_updates_baseline_without_regression_exit(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    baseline = tmp_path / "baseline.json"
    report_html = tmp_path / "report.html"
    record = {
        "id": "twin-01",
        "category": "external-schema-ref",
        "detector": "schema",
        "expected_ids": ["MCP053"],
        "emitted_ids": ["MCP053"],
        "predicted": "catch",
        "result": "CAUGHT",
    }
    results.write_text(json.dumps({"twins": [record]}), encoding="utf-8")

    _, exit_code = build_report(results, baseline, report_html, accept=True)

    assert exit_code == 0
    assert json.loads(baseline.read_text(encoding="utf-8"))["twins"][0]["id"] == "twin-01"
