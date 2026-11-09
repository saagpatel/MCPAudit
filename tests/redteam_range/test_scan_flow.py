"""Exercise the generated range and regression baseline as a complete offline flow."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.range.gen.__main__ import generate
from redteam.range.harness.scan import scan
from redteam.range.mutations import OPERATORS
from redteam.range.report.report import build_report


def test_extension_and_forced_injection_regression(tmp_path: Path) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    normal = scan(twins)
    records = normal["twins"]
    control = normal["control"]
    assert isinstance(records, list) and len(records) == 31
    assert isinstance(control, dict) and control["expected_id_findings"] == []
    assert [item["id"] for item in records] == [operator.id for operator in OPERATORS]
    assert all(not item["provenance"] and not item["unexpected_ids"] for item in records)
    assert all(
        set(item["emitted_ids"]) <= set(item["expected_ids"]) | set(item["allowed_collateral"])
        for item in records
    )
    assert control["detector_provenance"]["pkgverify"] == []
    assert all(
        next(item for item in records if item["id"] == name)["result"] == "MISSED"
        for name in ("hidden-desc", "hidden-param")
    )
    extension = next(item for item in records if item["category"] == "external-schema-ref")
    assert extension["result"] == "CAUGHT" and "MCP053" in extension["emitted_ids"]

    results, baseline, html = (tmp_path / name for name in ("results.json", "baseline.json", "report.html"))
    results.write_text(json.dumps(normal), encoding="utf-8")
    report, status = build_report(results, baseline, html, accept=True)
    assert status == 0 and "external-schema-ref" in report
    matrix_header = next(line for line in report.splitlines() if line.startswith("| Category | "))
    assert [cell.strip() for cell in matrix_header.strip("|").split("|")][1:] == [
        operator.id for operator in OPERATORS
    ]
    rows = [
        line.split(" | ")[0][2:]
        for line in report.splitlines()
        if line.startswith("| ") and " | completed | " in line
    ]
    assert rows == [operator.id for operator in OPERATORS]
    assert len(json.loads(baseline.read_text(encoding="utf-8"))["twins"]) == 31
    assert all(item["id"] in html.read_text(encoding="utf-8") for item in records)

    disabled = scan(twins, disabled={"injection"})
    results.write_text(json.dumps(disabled), encoding="utf-8")
    report, status = build_report(results, baseline, html)
    injection = [item for item in records if item["detector"] == "injection"]
    assert injection and status == 1
    assert all(f"{item['id']}: {item['result']} → NOT_RUN" in report for item in injection)
