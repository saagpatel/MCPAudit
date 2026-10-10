"""Fixture-backed privacy, coverage and presentation contracts for share cards."""

from datetime import timedelta
from pathlib import Path

import pytest

from mcp_audit.checkup import generate_card, load_previous, sticker, vitals
from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    ConnectionMode,
    InjectionFinding,
    InjectionSeverity,
)

FIXTURE = Path(__file__).parent / "fixtures/reports/sample_audit_report.json"


@pytest.fixture
def report() -> AuditReport:
    report = AuditReport.model_validate_json(FIXTURE.read_text())
    report.audits[0].permissions = []
    report.audits[0].capability_findings = []
    report.audits[0].drift_findings = []
    report.policy_result = None
    report.coverage = {
        key: CheckCoverage(state="complete", reason="synthetic fixture completed")
        for key in ("config_health", "metadata", "permissions", "capabilities", *OPTIONAL_CHECKS)
    }
    for key in OPTIONAL_CHECKS:
        if key not in {"inject_check", "trifecta_check", "shadow_check"}:
            report.coverage[key] = CheckCoverage(state="not_requested", reason="check not requested")
    return report


def test_default_card_and_sticker_exclude_fixture_identifiers(report: AuditReport) -> None:
    output = generate_card(report) + sticker(report)
    server = report.audits[0].server
    private = [
        report.hostname,
        server.name,
        server.config_path,
        *server.env_keys,
        *server.headers_keys,
        *server.args,
        *(t.name for t in report.audits[0].tools),
        *(t.description for t in report.audits[0].tools),
        *(r.uri for r in report.audits[0].resources),
    ]
    assert all(value not in output for value in private if value)
    assert "deep scan" in output
    assert "reach and hygiene, not a safety certificate" in output
    assert "09 May 2026" in output
    assert output.count('<li class="') == 4
    assert "width:1200px;height:630px" in output
    assert "<script" not in output and "https://" not in output


def test_names_opt_in_is_escaped_and_does_not_add_other_identifiers(report: AuditReport) -> None:
    report.audits[0].server.name = '<script>alert("fixture")</script>'
    output = generate_card(report, names=True)
    assert "&lt;script&gt;" in output
    assert "<script>" not in output
    assert report.hostname not in output
    assert report.audits[0].server.config_path not in output
    assert all(key not in output for key in report.audits[0].server.env_keys)
    assert "execute_command" not in output


@pytest.mark.parametrize("state", ["not_run", "partial", "not_requested"])
def test_unchecked_vitals_never_claim_clean(report: AuditReport, state: str) -> None:
    report.coverage["inject_check"] = CheckCoverage.model_validate({"state": state, "reason": "fixture"})
    output = generate_card(report)
    assert "not checked" in output
    if state in {"not_run", "partial"}:
        assert 'class="big preview">Preview' in output
        assert "· preview" in sticker(report)


def test_config_only_is_preview_even_with_high_numeric_risk(report: AuditReport) -> None:
    report.connection_mode = ConnectionMode.SKIPPED
    report.coverage["metadata"] = CheckCoverage(state="not_run", reason="connections disabled")
    assert 'class="big preview">Preview' in generate_card(report)
    assert "deep scan" not in generate_card(report)
    assert report.audits[0].risk_score is not None
    assert report.audits[0].risk_score.composite == 8.0


def test_observed_counts_survive_partial_coverage_without_exposing_evidence(report: AuditReport) -> None:
    report.audits[0].injection_findings = [
        InjectionFinding(
            tool_name="private-fixture-tool",
            severity=InjectionSeverity.MEDIUM,
            pattern_name="instruction_override",
            matched_text="private-fixture-evidence",
            description="Synthetic instruction-shaped metadata.",
        )
    ]
    report.coverage["inject_check"] = CheckCoverage(state="partial", reason="fixture listing incomplete")
    output = generate_card(report)
    assert 'class="val">1 · partial' in output
    assert "private-fixture-tool" not in output
    assert "private-fixture-evidence" not in output


@pytest.mark.parametrize(
    "spec, floating",
    [("fixture", 1), ("fixture@latest", 1), ("fixture@^1.0.0", 1), ("@scope/fixture@1.2.3", 0)],
)
def test_auto_updating_count_uses_local_package_reference_parser(
    report: AuditReport, spec: str, floating: int
) -> None:
    report.audits[0].server.command = "npx"
    report.audits[0].server.args = ["-y", spec]
    assert vitals(report)[-1] == ("Auto-updating launches", floating, True)


def test_grade_and_optional_comparison_reuse_d6_without_score_changes(report: AuditReport) -> None:
    before = report.model_copy(deep=True)
    before.scan_timestamp -= timedelta(hours=1)
    before.config_health_findings = [
        ConfigHealthFinding(
            finding_type="shell_wrapper_launch",
            severity=ConfigHealthSeverity.MEDIUM,
            server_name=before.audits[0].server.name,
            summary="Fixture launch requires review.",
            remediation="Review the fixture launch.",
        )
    ]
    assert before.ux_summary.grade == "F"
    output = generate_card(report, previous=before)
    assert 'class="big A">A' in output
    assert "1 fewer review actions · was F in previous run" in output
    assert 'class="big F">F' in generate_card(before)
    assert "passed" not in generate_card(before)
    before.audits[0].server.name = "different-fixture"
    assert "fewer review actions" not in generate_card(report, previous=before)


def test_preview_and_newer_reports_do_not_produce_glow_up(report: AuditReport) -> None:
    before = report.model_copy(deep=True)
    before.scan_timestamp += timedelta(hours=1)
    assert "previous run" not in generate_card(report, previous=before)
    before.scan_timestamp = before.scan_timestamp.replace(tzinfo=None)
    assert "previous run" not in generate_card(report, previous=before)
    before.scan_timestamp -= timedelta(hours=2)
    before.connection_mode = ConnectionMode.SKIPPED
    assert "previous run" not in generate_card(report, previous=before)


def test_previous_is_explicit_and_validation_errors_do_not_echo_content(tmp_path: Path) -> None:
    assert load_previous(None) is None
    assert load_previous(FIXTURE) is not None
    previous = tmp_path / "previous.json"
    previous.write_text('{"hostname": "private-fixture-marker"}')
    with pytest.raises(ValueError, match="Previous report is not valid AuditReport JSON") as exc:
        load_previous(previous)
    assert "private-fixture-marker" not in str(exc.value)


def test_previous_rejects_non_regular_and_oversized_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        load_previous(tmp_path)
    oversized = tmp_path / "oversized.json"
    with oversized.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="16 MiB limit"):
        load_previous(oversized)


def test_card_keeps_json_grade_and_schema_contract(report: AuditReport) -> None:
    score = report.audits[0].risk_score
    generate_card(report)
    assert report.model_dump(mode="json")["ux_summary"]["grade"] == "A"
    assert report.schema_version == 1
    assert report.audits[0].risk_score == score
