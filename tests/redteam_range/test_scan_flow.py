"""Exercise the generated range and regression baseline as a complete offline flow."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from redteam.range.gen.__main__ import generate
from redteam.range.harness import scan as scan_module
from redteam.range.harness.adapter import AdapterFinding, AdapterResult, DetectorStatus, run_detectors
from redteam.range.harness.scan import scan
from redteam.range.mutations import OPERATORS
from redteam.range.report.report import build_report
from redteam.range.rerun import __main__ as rerun_module


def test_extension_and_forced_injection_regression(tmp_path: Path) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    normal = scan(twins)
    records = normal["twins"]
    control = normal["control"]
    assert isinstance(records, list) and len(records) == 31
    assert isinstance(control, dict) and control["expected_id_findings"] == []
    assert control["result"] == "CLEAN" and control["not_applicable"] == ["pkgverify"]
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
    report, status = build_report(results, baseline, html, accept=True, index_path=twins / "index.json")
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
    report, status = build_report(results, baseline, html, index_path=twins / "index.json")
    injection = [item for item in records if item["detector"] == "injection"]
    assert injection and status == 1
    assert all(f"{item['id']}: {item['result']} → NOT_RUN" in report for item in injection)


def test_incomplete_and_mocked_are_scoped_to_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    original = run_detectors
    calls = 0

    def run(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)  # type: ignore[arg-type]
        calls += 1
        if calls == 1:
            result.statuses["injection"] = DetectorStatus("incomplete", "target truncated")
            result.provenance["pkgverify"] = {"MOCKED"}
        elif calls == 2:
            result.statuses["permissions"] = DetectorStatus("incomplete", "other truncated")
            result.provenance["injection"] = {"MOCKED"}
        return result

    monkeypatch.setattr(scan_module, "run_detectors", run)
    data = scan(twins)
    records = data["twins"]
    assert isinstance(records, list)
    first, second = records[:2]
    assert first["result"] == "NOT_RUN" and first["reason"] == "target truncated"
    assert first["provenance"] == []
    assert second["result"] in {"CAUGHT", "MISSED"} and second["provenance"] == ["MOCKED"]
    assert second["statuses"]["permissions"]["reason"] == "other truncated"
    results, baseline, output = (tmp_path / name for name in ("results.json", "baseline.json", "report.html"))
    results.write_text(json.dumps(data), encoding="utf-8")
    baseline.write_text(json.dumps(data), encoding="utf-8")
    report, _ = build_report(results, baseline, output, index_path=twins / "index.json")
    assert "permissions: other truncated" in report


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_control_finding_threshold_includes_unexpected_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, severity: str
) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    calls = 0

    def run(*args: object, **kwargs: object) -> AdapterResult:
        nonlocal calls
        result = run_detectors(*args, **kwargs)  # type: ignore[arg-type]
        calls += 1
        if calls == len(OPERATORS) + 1:
            result.findings.append(AdapterFinding("MCP999", severity, None, "schema", "control only"))
        return result

    monkeypatch.setattr(scan_module, "run_detectors", run)
    data = scan(twins)
    control = data["control"]
    assert isinstance(control, dict)
    assert control["expected_id_findings"] == []
    assert control["emitted_ids"] == ["MCP999"]
    assert control["result"] == ("FINDINGS" if severity in {"medium", "high", "critical"} else "CLEAN")


@pytest.mark.parametrize("defect", ["incomplete", "missing", "findings"])
@pytest.mark.parametrize("accept", [False, True])
def test_rerun_rejects_control_failure_with_unchanged_twins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, accept: bool
) -> None:
    twins = tmp_path / "twins"
    generate(twins)
    normal = scan(twins)
    baseline = tmp_path / "redteam/range/baseline.json"
    baseline.parent.mkdir(parents=True)
    baseline.write_text(json.dumps(normal), encoding="utf-8")
    original = baseline.read_bytes()
    calls = 0

    def run(*args: object, **kwargs: object) -> AdapterResult:
        nonlocal calls
        result = run_detectors(*args, **kwargs)  # type: ignore[arg-type]
        calls += 1
        if calls == len(OPERATORS) + 1:
            if defect == "missing":
                del result.statuses["schema"]
            elif defect == "incomplete":
                result.statuses["schema"] = DetectorStatus("incomplete", "control truncated")
            else:
                result.findings.append(AdapterFinding("MCP999", "medium", None, "schema", "control only"))
        return result

    monkeypatch.setattr(scan_module, "run_detectors", run)
    monkeypatch.setattr(rerun_module, "ROOT", tmp_path)
    monkeypatch.setattr(rerun_module, "RESULTS", tmp_path / "results.json")
    monkeypatch.setattr(rerun_module, "generate", lambda: generate(twins))
    monkeypatch.setattr(rerun_module, "scan", lambda: scan(twins))
    monkeypatch.setattr(sys, "argv", ["rerun", *(["--accept"] if accept else [])])

    assert rerun_module.main() == 1
    assert baseline.read_bytes() == original
    actual = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert actual["twins"] == normal["twins"]
    assert actual["control"]["result"] == ("FINDINGS" if defect == "findings" else "INCOMPLETE")


def test_scan_rejects_empty_index(tmp_path: Path) -> None:
    (tmp_path / "index.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty list"):
        scan(tmp_path)
