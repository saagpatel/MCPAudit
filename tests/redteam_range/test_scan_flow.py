"""Exercise the generated range and regression baseline as a complete offline flow."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.range.gen.__main__ import generate
from redteam.range.harness.scan import scan
from redteam.range.report.report import build_report


def test_extension_and_forced_injection_regression(tmp_path: Path) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    normal = scan(twins)
    records = normal["twins"]
    control = normal["control"]
    assert isinstance(records, list) and len(records) == 31
    assert isinstance(control, dict) and control["expected_id_findings"] == []
    extension = next(item for item in records if item["category"] == "external-schema-ref")
    assert extension["result"] == "CAUGHT" and "MCP053" in extension["emitted_ids"]

    results, baseline, html = (tmp_path / name for name in ("results.json", "baseline.json", "report.html"))
    results.write_text(json.dumps(normal), encoding="utf-8")
    report, status = build_report(results, baseline, html, accept=True)
    assert status == 0 and "external-schema-ref" in report
    assert len(json.loads(baseline.read_text(encoding="utf-8"))["twins"]) == 31
    assert all(item["id"] in html.read_text(encoding="utf-8") for item in records)

    disabled = scan(twins, disabled={"injection"})
    results.write_text(json.dumps(disabled), encoding="utf-8")
    report, status = build_report(results, baseline, html)
    injection = [item for item in records if item["detector"] == "injection"]
    assert injection and status == 1
    assert all(f"{item['id']}: {item['result']} → NOT_RUN" in report for item in injection)
