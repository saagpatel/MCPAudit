"""Reporting and policy coverage for signed-pin verification failures."""

from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Literal

import pytest
from rich.console import Console

from mcp_audit.evidence_enforcement import observed_evidence_from_report
from mcp_audit.finding_display import finding_views
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    PinIntegrityFinding,
    PinVerification,
    PinVerificationState,
    ServerAudit,
)
from mcp_audit.policy import evaluate_policy, load_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.suppressions import IgnoreEntry, apply_suppressions, unsuppressed_report
from tests.conftest import make_server_config

FailedPinState = Literal["untrusted_signer", "bad_signature", "tampered_entry"]


def _report(state: FailedPinState = "bad_signature") -> AuditReport:
    audit = ServerAudit(
        server=make_server_config(name="synthetic-server"),
        connection_status="connected",
        pin_verification=PinVerification(state=PinVerificationState(state), kid="0123456789abcdef"),
        pin_integrity_findings=[
            PinIntegrityFinding(
                state=state,
                server_name="synthetic-server",
                kid="0123456789abcdef",
                summary="Synthetic signed pin verification failure.",
            )
        ],
    )
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="synthetic-host",
        os_platform="test",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.0,
    )


@pytest.mark.parametrize("state", ["untrusted_signer", "bad_signature", "tampered_entry"])
def test_failed_pin_verification_is_typed_and_serialized(state: FailedPinState) -> None:
    report = _report(state)

    assert report.audits[0].pin_verification == PinVerification(
        state=PinVerificationState(state), kid="0123456789abcdef"
    )
    serialized = report.model_dump(mode="json")
    audit_json = serialized["audits"][0]
    assert audit_json["pin_verification"] == {"state": state, "kid": "0123456789abcdef"}
    assert audit_json["pin_integrity_findings"][0]["rule_id"] == "MCP027"


def test_pin_integrity_finding_is_high_mcp027_sarif() -> None:
    sarif = SarifGenerator().generate(_report())
    run = sarif["runs"][0]
    finding = next(result for result in run["results"] if result["ruleId"] == "MCP027")
    rule = next(rule for rule in run["tool"]["driver"]["rules"] if rule["id"] == "MCP027")

    assert finding["level"] == "error"
    assert finding["properties"]["severity"] == "high"
    assert finding["properties"]["state"] == "bad_signature"
    assert "Synthetic signed pin verification failure." in finding["message"]["text"]
    assert rule["defaultConfiguration"]["level"] == "error"


def test_pin_integrity_appears_in_summary_terminal_and_html() -> None:
    report = _report()

    summary = report.ensure_review_summary()
    assert summary.action_counts["high"] == 1
    assert summary.action_count == 1
    assert summary.actions[0].terminal is not None
    assert summary.actions[0].terminal.rule == "MCP027"
    assert summary.actions[0].terminal.connected is False
    assert any(view.rule_id == "MCP027" for view in finding_views(report))

    buffer = StringIO()
    ReportGenerator(Console(file=buffer, width=120, force_terminal=False)).render_terminal(
        report, details=True
    )
    terminal = buffer.getvalue()
    assert "MCP027" in terminal
    assert "Synthetic signed pin verification failure." in terminal

    html = HtmlReportGenerator().generate(report)
    assert "MCP027" in html
    assert "Synthetic signed pin verification failure." in html


def test_pin_integrity_summary_redacts_secrets_and_invalid_kids() -> None:
    report = _report()
    finding = PinIntegrityFinding(
        state="untrusted_signer",
        server_name="synthetic-server",
        kid="not-a-hex-kid\napi_key=synthetic-fake-secret",
        summary="Pin verification failed; api_key=synthetic-fake-secret",
    )

    assert report.audits[0].pin_verification is not None
    assert finding.kid is None
    assert finding.summary == "Pin verification failed; api_key=<redacted>"
    report.audits[0].pin_integrity_findings = [finding]
    serialized = report.redacted().model_dump(mode="json")
    data = serialized["audits"][0]["pin_integrity_findings"][0]
    assert data["kid"] is None
    assert "synthetic-fake-secret" not in str(serialized)
    assert data["summary"] == "Pin verification failed; api_key=<redacted>"


def test_pin_integrity_policy_is_opt_in_and_gates_mcp027(tmp_path: Path) -> None:
    report = _report()
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("fail_on:\n  pin_integrity: true\n")

    enabled = evaluate_policy(report, load_policy(policy_file))
    assert not enabled.passed
    assert [(violation.rule, violation.severity) for violation in enabled.violations] == [
        ("fail_on.pin_integrity", "high")
    ]

    policy_file.write_text("fail_on:\n  pin_integrity: false\n")
    disabled = evaluate_policy(report, load_policy(policy_file))
    assert disabled.passed

    policy_file.write_text("{}\n")
    default = evaluate_policy(report, load_policy(policy_file))
    assert default.passed


def test_pin_integrity_policy_value_must_be_boolean(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("fail_on:\n  pin_integrity: high\n")

    with pytest.raises(ValueError, match="fail_on.pin_integrity must be a boolean"):
        load_policy(policy_file)


def test_pin_integrity_can_be_suppressed_only_with_explicit_reason() -> None:
    report = _report()
    apply_suppressions(
        report,
        [
            IgnoreEntry(
                rule="MCP027",
                server="synthetic-server",
                tool="*",
                reason="Reviewed synthetic baseline handling.",
            )
        ],
    )

    assert len(report.suppressed) == 1
    assert report.suppressed[0].rule_id == "MCP027"
    assert not unsuppressed_report(report).audits[0].pin_integrity_findings


def test_pin_integrity_marks_observed_evidence_as_drifted() -> None:
    evidence = observed_evidence_from_report(
        _report(),
        origin="fixture://pin-integrity",
        server_name="synthetic-server",
        canonical_source_sha256="sha256:" + "0" * 64,
        provenance=["synthetic-pin-integrity-fixture"],
    )

    assert evidence.drifted


def test_pin_verification_state_vocabulary_is_complete() -> None:
    assert {state.value for state in PinVerificationState} == {
        "verified",
        "unsigned",
        "untrusted_signer",
        "bad_signature",
        "tampered_entry",
        "retired_key",
        "schema_outdated",
    }
