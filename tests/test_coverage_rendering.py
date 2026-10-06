"""Coverage-state rendering tests for terminal and HTML reports."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console

from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport
from mcp_audit.report import ReportGenerator

_FIXTURE = Path("tests/fixtures/reports/config_only_report.json")


def _report_with_coverage(**coverage: dict[str, str]) -> AuditReport:
    report = AuditReport.model_validate_json(_FIXTURE.read_text())
    data = report.model_dump(mode="python")
    data["coverage"] = coverage
    return AuditReport.model_validate(data)


def test_legacy_report_marks_coverage_unknown_in_terminal_and_html() -> None:
    report = AuditReport.model_validate_json(_FIXTURE.read_text())

    output = ReportGenerator(
        console=Console(file=io.StringIO(), width=120, highlight=False)
    ).capture_terminal(report)
    html = HtmlReportGenerator().generate(report)

    assert "Coverage unknown: checks were not recorded" in output
    assert "Runtime security: UNKNOWN" in output
    assert "Coverage unknown" in html
    assert "Runtime security: UNKNOWN" in html
    assert "Checked:</strong>" not in html


def test_config_only_metadata_and_unrequested_runtime_are_explicit() -> None:
    report = _report_with_coverage(
        metadata={"state": "not_run", "reason": "connections disabled"},
        runtime_security={"state": "not_requested", "reason": "canary disabled"},
        permissions={"state": "complete", "reason": ""},
        inject_check={"state": "not_requested", "reason": "disabled"},
    )

    output = ReportGenerator(
        console=Console(file=io.StringIO(), width=120, highlight=False)
    ).capture_terminal(report)
    html = HtmlReportGenerator().generate(report)

    assert "Checked: Permissions" in output
    assert "Metadata checks not run: connections disabled" in output
    assert "Runtime security: NOT CHECKED" in output
    assert "Inject Check" not in output
    assert "Metadata checks not run: connections disabled" in html
    assert "Runtime security: NOT CHECKED (canary disabled)" in html
    assert "Hidden instructions: NOT REQUESTED" in html


def test_partial_runtime_coverage_has_incomplete_banner_and_escapes_reason() -> None:
    report = _report_with_coverage(
        runtime_security={"state": "partial", "reason": "<page limit> reached; no eligible tools"},
    )

    output = ReportGenerator(
        console=Console(file=io.StringIO(), width=120, highlight=False)
    ).capture_terminal(report)
    html = HtmlReportGenerator().generate(report)

    assert "Runtime security: PARTIAL" in output
    assert "Audit coverage is incomplete" in output
    assert "Audit coverage is incomplete" in html
    assert "&lt;page limit&gt; reached; no eligible tools" in html
    assert "<page limit>" not in html


def test_sparse_coverage_marks_missing_checks_unknown() -> None:
    report = _report_with_coverage(
        permissions={"state": "complete", "reason": "configuration inspected"},
    )

    output = ReportGenerator().capture_terminal(report)
    html = HtmlReportGenerator().generate(report)

    assert "Coverage unknown: checks not recorded:" in output
    assert "runtime_security" in output
    assert "Runtime security: UNKNOWN" in output
    assert 'aria-label="Coverage unknown"' in html
    assert "Coverage unknown: checks not recorded:" in html
    assert "runtime_security" in html
    assert "Runtime security: UNKNOWN" in html
