import json
from pathlib import Path

import pytest

from redteam.range.harness.adapter import DETECTOR_KEYS
from redteam.range.report.report import ControlRecord, Result, TwinRecord, build_report, main


def _twin(twin_id: str = "twin-01", result: Result = "CAUGHT") -> TwinRecord:
    return {
        "id": twin_id,
        "category": "external-schema-ref",
        "detector": "schema",
        "expected_ids": ["MCP053"],
        "emitted_ids": ["MCP053"] if result == "CAUGHT" else [],
        "predicted": "catch",
        "result": result,
        "statuses": {"schema": {"state": "completed"}},
    }


def _control() -> ControlRecord:
    return {
        "result": "CLEAN",
        "emitted_ids": [],
        "expected_id_findings": [],
        "statuses": {key: {"state": "completed"} for key in DETECTOR_KEYS},
    }


def _write_scan(path: Path, twins: list[TwinRecord], control: ControlRecord | None = None) -> None:
    path.write_text(
        json.dumps({"twins": twins, "control": _control() if control is None else control}), encoding="utf-8"
    )


def _write_index(tmp_path: Path, ids: list[str]) -> None:
    directory = tmp_path / "twins"
    directory.mkdir(exist_ok=True)
    (directory / "index.json").write_text(json.dumps(ids), encoding="utf-8")


@pytest.mark.parametrize("previous", ["CAUGHT", "MISSED"])
@pytest.mark.parametrize("explicit_result", [True, False])
def test_report_renders_tables_and_flags_not_run_regression(
    tmp_path: Path, previous: Result, explicit_result: bool
) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    twin: TwinRecord = {
        **_twin(result=previous),
        "category": "schema <unsafe>",
        "detector": "injection",
        "expected_ids": ["MCP001"],
        "allowed_collateral": ["MCP002"],
        "emitted_ids": [],
        "provenance": ["MOCKED"],
        "unexpected_ids": [],
        "reason": "disabled by caller",
    }
    # Even an explicit stale CAUGHT result cannot override disabled evidence.
    current: TwinRecord = {**twin, "statuses": {"injection": {"state": "disabled"}}}
    if not explicit_result:
        del current["result"]
    _write_scan(results, [current])
    _write_scan(baseline, [{**twin, "statuses": {"injection": {"state": "completed"}}}])
    _write_index(tmp_path, ["twin-01"])

    report, exit_code = build_report(results, baseline, report_html)

    assert exit_code == 1
    assert f"twin-01: {previous} → NOT_RUN" in report
    assert "schema <unsafe>" in report
    html_output = report_html.read_text(encoding="utf-8")
    assert "<table>" in html_output
    assert "&lt;unsafe&gt;" in html_output
    assert "MOCKED" in html_output


def test_accept_updates_baseline_without_regression_exit(tmp_path: Path) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    _write_scan(results, [_twin()])
    _write_index(tmp_path, ["twin-01"])

    _, exit_code = build_report(results, baseline, report_html, accept=True)

    assert exit_code == 0
    assert json.loads(baseline.read_text(encoding="utf-8"))["twins"][0]["id"] == "twin-01"


@pytest.mark.parametrize("change", ["removed", "renamed", "added", "category", "detector"])
def test_inventory_and_target_changes_require_acceptance(tmp_path: Path, change: str) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    previous = [_twin("retained"), _twin("external-schema-ref")]
    current: list[TwinRecord] = [twin.copy() for twin in previous]
    if change == "removed":
        current.pop()
    elif change == "renamed":
        current[-1]["id"] = "renamed"
    elif change == "added":
        current.append(_twin("new"))
    elif change == "category":
        current[-1]["category"] = "injection"
    else:
        current[-1]["detector"] = "injection"
        current[-1]["statuses"] = {"injection": {"state": "completed"}}
    _write_scan(baseline, previous)
    _write_scan(results, current)
    _write_index(tmp_path, [twin["id"] for twin in current])

    report, status = build_report(results, baseline, report_html)

    assert status == (0 if change == "added" else 1)
    if change in {"removed", "renamed"}:
        assert "external-schema-ref: twin removed" in report
    if change in {"renamed", "added"}:
        added_id = "renamed" if change == "renamed" else "new"
        assert f"Additions:\n- {added_id}: twin added" in report
    if change in {"category", "detector"}:
        assert f"external-schema-ref: {change} changed:" in report
    if change == "added":
        assert "Regressions: 0;" in report
    assert build_report(results, baseline, report_html, accept=True)[1] == 0
    assert build_report(results, baseline, report_html)[1] == 0


@pytest.mark.parametrize("state", ["FINDINGS", "INCOMPLETE"])
@pytest.mark.parametrize("existing_baseline", [True, False])
def test_control_failure_blocks_report_and_accept_independently_of_twins(
    tmp_path: Path, state: str, existing_baseline: bool
) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    control = _control()
    control["result"] = "FINDINGS" if state == "FINDINGS" else "INCOMPLETE"
    _write_scan(results, [_twin()], control)
    _write_scan(baseline, [_twin()])
    _write_index(tmp_path, ["twin-01"])
    report, status = build_report(results, baseline, report_html)
    assert status == 1 and "Regressions: 0;" in report
    assert f"Result: {state}." in report

    original = baseline.read_bytes()
    if not existing_baseline:
        baseline.unlink()
    with pytest.raises(ValueError, match=f"cannot accept baseline: clean control is {state}"):
        build_report(results, baseline, report_html, accept=True)
    if existing_baseline:
        assert baseline.read_bytes() == original
    else:
        assert not baseline.exists()


@pytest.mark.parametrize(
    "defect", ["missing_status", "disabled", "incomplete", "finding", "invalid_na", "unclassified_finding"]
)
def test_stale_clean_label_cannot_hide_control_failure(tmp_path: Path, defect: str) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    control = _control()
    if defect == "missing_status":
        del control["statuses"]["schema"]
    elif defect == "finding":
        control["medium_plus_findings"] = ["MCP999"]
    elif defect == "unclassified_finding":
        control["emitted_ids"] = ["MCP999"]
    elif defect == "invalid_na":
        control["not_applicable"] = ["schema"]
        control["statuses"]["schema"] = {"state": "not_run"}
    else:
        control["statuses"]["schema"] = {"state": defect}
    _write_scan(results, [_twin()], control)
    _write_scan(baseline, [_twin()])
    _write_index(tmp_path, ["twin-01"])
    assert build_report(results, baseline, report_html)[1] == 1
    with pytest.raises(ValueError, match="cannot accept baseline"):
        build_report(results, baseline, report_html, accept=True)


@pytest.mark.parametrize("state", ["not_run", "disabled", "incomplete"])
@pytest.mark.parametrize("reason", ["baseline capture failed", "current package hash unavailable"])
def test_only_exact_package_not_applicable_exception_is_clean(
    tmp_path: Path, state: str, reason: str
) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    control = _control()
    control["not_applicable"] = ["pkgverify"]
    control["statuses"]["pkgverify"] = {"state": state, "reason": reason}
    _write_scan(results, [_twin()], control)
    _write_scan(baseline, [_twin()])
    _write_index(tmp_path, ["twin-01"])
    report, status = build_report(results, baseline, report_html)
    assert status == (0 if state == "not_run" and reason == "baseline capture failed" else 1)
    assert "base has no package references" in report


@pytest.mark.parametrize("accept", [False, True])
@pytest.mark.parametrize(
    "defect", ["missing", "extra", "duplicate", "empty", "index_duplicate", "index_missing"]
)
def test_invalid_inventory_never_passes_or_replaces_baseline(
    tmp_path: Path, accept: bool, defect: str
) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    twins = [_twin(), _twin("twin-02")]
    _write_scan(baseline, twins)
    original = baseline.read_bytes()
    _write_index(tmp_path, [twin["id"] for twin in twins])
    if defect == "missing":
        twins.pop()
    elif defect == "extra":
        twins.append(_twin("extra"))
    elif defect == "duplicate":
        twins.append(_twin())
    elif defect == "empty":
        twins.clear()
    elif defect == "index_duplicate":
        _write_index(tmp_path, ["twin-01", "twin-01"])
    else:
        (tmp_path / "twins/index.json").unlink()
    _write_scan(results, twins)
    with pytest.raises((ValueError, FileNotFoundError)):
        build_report(results, baseline, report_html, accept=accept)
    assert baseline.read_bytes() == original
    assert not report_html.exists()


def test_missing_control_is_rejected_by_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    results.write_text(json.dumps({"twins": [_twin()]}), encoding="utf-8")
    status = main(
        ["--results", str(results), "--baseline", str(baseline), "--html", str(report_html), "--accept"]
    )
    assert status == 2
    assert "clean control must be an object" in capsys.readouterr().err
    assert not baseline.exists()


@pytest.mark.parametrize("defect", ["duplicate", "empty"])
def test_invalid_baseline_inventory_cannot_pass(tmp_path: Path, defect: str) -> None:
    results, baseline, report_html = (
        tmp_path / name for name in ("results.json", "baseline.json", "report.html")
    )
    _write_scan(results, [_twin()])
    _write_index(tmp_path, ["twin-01"])
    _write_scan(baseline, [_twin(), _twin()] if defect == "duplicate" else [])
    with pytest.raises(ValueError, match="duplicate twin id|non-empty twins list"):
        build_report(results, baseline, report_html)
    assert not report_html.exists()
