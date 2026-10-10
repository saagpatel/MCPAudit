"""Tests for the single-file HTML report generator.

Covers:
  - Well-formed document scaffold (doctype, title, body close)
  - Summary stats + per-server section rendering
  - Every finding type surfaces (permission, injection, ssrf, trifecta,
    escalation, drift, fleet shadowing, policy, config health)
  - SECURITY: attacker-influenceable text (tool descriptions / matched text) is
    HTML-escaped so the report can never become an XSS vector
  - Empty report renders qualified absence without implying checks ran
  - Loads the escalation fixture and renders it
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Literal, get_origin

import pytest
from click.testing import CliRunner
from pydantic import BaseModel

from mcp_audit.cli import main
from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.htmlreport import HtmlReportGenerator, _hide_identifiers
from mcp_audit.models import (
    AuditReport,
    CapabilityFinding,
    CapabilityTarget,
    CheckCoverage,
    ClientType,
    Confidence,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    ConnectionMode,
    EgressFinding,
    EgressKind,
    EgressSeverity,
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    PolicyResult,
    PolicyViolation,
    RiskScore,
    ServerAudit,
    ServerConfig,
    SsrfFinding,
    SsrfSeverity,
    TransportType,
    UxSummary,
)
from mcp_audit.ux_summary import actions

_GEN = HtmlReportGenerator()

_XSS = "<script>alert('pwned')</script>"


def _server_config(name: str = "srv") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )


def _report_with_findings() -> AuditReport:
    audit = ServerAudit(
        server=_server_config(f"evil-server{_XSS}"),  # attacker text in the server name
        connection_status="connected",
        connection_error=_XSS,  # attacker text in the error string
        risk_score=RiskScore(
            composite=8.5,
            file_access=9.0,
            network_access=5.0,
            shell_execution=8.0,
            destructive=3.0,
            exfiltration=7.0,
        ),
        permissions=[
            PermissionFinding(
                category=PermissionCategory.SHELL_EXEC,
                confidence=Confidence.HIGH,
                evidence=[_XSS],  # attacker text in evidence
                tool_name="run",
            )
        ],
        injection_findings=[
            InjectionFinding(
                tool_name="run",
                severity=InjectionSeverity.HIGH,
                pattern_name="ignore_instructions",
                matched_text=_XSS,  # attacker text in matched excerpt
                description="injection",
            )
        ],
        escalation_findings=[
            EscalationFinding(
                kind=EscalationKind.CAPABILITY,
                severity=EscalationSeverity.HIGH,
                server_name="evil-server",
                tool_name="run",
                gained_categories=[PermissionCategory.SHELL_EXEC],
                description="escalated",
            )
        ],
    )
    return AuditReport(
        scan_timestamp=datetime(2026, 5, 31, 12, 0, tzinfo=UTC),
        hostname="host",
        os_platform="Test",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=1,
        audits=[audit],
        scan_duration_seconds=0.1,
        policy_result=PolicyResult(
            passed=False,
            violations=[
                PolicyViolation(
                    rule="fail_on.escalation",
                    message="escalation finding",
                    server_name="evil-server",
                    tool_name="run",
                    severity="high",
                )
            ],
        ),
    )


class TestDocumentScaffold:
    def test_renders_valid_html_document(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>mcp-audit report</title>" in html
        assert html.rstrip().endswith("</body></html>")

    def test_summary_and_server_section_present(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert "MCP Permission Audit" in html
        assert "evil-server" in html
        assert "High-risk servers" in html

    def test_finding_sections_present(self) -> None:
        html = _GEN.generate(_report_with_findings())
        for label in ("Permissions", "Prompt-injection", "Capability escalation", "Policy"):
            assert label in html
        assert "MCP018" in html  # escalation rule id
        assert "ignore_instructions" in html


class TestXssSafety:
    def test_attacker_markup_is_escaped_not_raw(self) -> None:
        html = _GEN.generate(_report_with_findings())
        # Raw script tag must NOT appear — only the escaped form.
        assert _XSS not in html
        assert "&lt;script&gt;" in html

    def test_no_raw_angle_bracket_payload_anywhere(self) -> None:
        html = _GEN.generate(_report_with_findings())
        assert "<script>alert" not in html


class TestEmptyReport:
    def test_empty_report_still_valid(self) -> None:
        report = AuditReport(
            scan_timestamp=datetime(2026, 5, 31, 12, 0, tzinfo=UTC),
            hostname="host",
            os_platform="Test",
            servers_discovered=0,
            servers_connected=0,
            servers_failed=0,
            total_tools=0,
            high_risk_servers=0,
            audits=[],
            scan_duration_seconds=0.0,
        )
        html = _GEN.generate(report)
        assert html.startswith("<!DOCTYPE html>")
        assert "No findings recorded." in html
        assert "None." not in html
        assert "Preview" in html
        assert "Coverage unknown" in html


def test_config_only_report_names_connection_mode() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/config_only_report.json").read_text()
    )
    report.connection_mode = ConnectionMode.SKIPPED
    html = _GEN.generate(report)
    assert "Connection mode" in html
    assert "Config only" in html


class TestFixtureRendering:
    def test_escalation_fixture_renders(self) -> None:
        fixture = Path("tests/fixtures/reports/escalation_report.json")
        report = AuditReport.model_validate_json(fixture.read_text())
        html = _GEN.generate(report)
        assert "rugpull-server" in html
        assert "MCP018" in html
        assert "shell_execution" in html


def test_pin_only_html_keeps_tool_column_without_severity() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    table = HtmlReportGenerator()._drift_table(report.audits[0])
    assert "<th>Tool</th>" in table and "<th>Severity</th>" not in table


def _summary_report(fixture: str = "sample_audit_report") -> AuditReport:
    report = AuditReport.model_validate_json(Path(f"tests/fixtures/reports/{fixture}.json").read_text())
    report.coverage = {
        key: CheckCoverage(state="complete", reason="synthetic fixture check completed")
        for key in ("config_health", "permissions", "capabilities", "metadata", *OPTIONAL_CHECKS)
    }
    if report.connection_mode == ConnectionMode.SKIPPED:
        for key in report.coverage:
            if key != "config_health":
                report.coverage[key] = CheckCoverage(state="not_run", reason="connections disabled")
    return report


@pytest.mark.parametrize("fixture", ["sample_audit_report", "config_only_report"])
def test_summary_html_golden(fixture: str) -> None:
    html = _GEN.generate(_summary_report(fixture))
    assert html == Path(f"tests/fixtures/html/{fixture}.html").read_text()


def test_summary_order_and_collapsed_log_preserve_original_rows() -> None:
    report = _summary_report()
    html = _GEN.generate(report)
    positions = [
        html.index(text)
        for text in (
            'aria-label="Summary"',
            'aria-label="Checked"',
            "Top fixes",
            "Worth a look ·",
            "FYI ·",
            "Your servers",
            "Full audit log",
        )
    ]
    assert positions == sorted(positions)
    assert '<details class="server-card">' in html
    assert '<details class="audit-log">' in html
    assert "<details open" not in html
    assert "runs commands" in html
    assert "EXAMPLE_TOKEN" in html and "/tmp/mcp.json" in html
    log = html.split("Full audit log</summary>", 1)[1]
    for audit in report.audits:
        for render in (
            _GEN._permissions_table,
            _GEN._injection_table,
            _GEN._ssrf_table,
            _GEN._egress_table,
            _GEN._trifecta_table,
            _GEN._escalation_table,
            _GEN._provenance_table,
            _GEN._integrity_table,
            _GEN._package_verify_table,
            _GEN._artifact_verify_table,
            _GEN._drift_table,
        ):
            assert render(audit) in log
    assert "Reach and hygiene, not a safety certificate." in html


def test_grade_is_additive_and_independent_of_numeric_score() -> None:
    report = _summary_report()
    audit = report.audits[0]
    audit.injection_findings = []
    audit.trifecta_findings = []
    audit.escalation_findings = []
    audit.drift_findings = []
    report.config_health_findings = []
    report.fleet_trifecta_findings = []
    report.shadowing_findings = []
    report.policy_result = None
    audit.permissions = []
    audit.capability_findings = []
    # Each changed raw report is a new presentation snapshot.
    assert report.model_copy().ux_summary == UxSummary(grade="A")
    baseline = audit.risk_score.model_dump() if audit.risk_score else None
    audit.permissions = [
        PermissionFinding(
            category=PermissionCategory.SHELL_EXEC,
            confidence=Confidence.HIGH,
            evidence=["run"],
            tool_name="run",
        )
    ]
    assert report.model_copy().ux_summary == UxSummary(grade="C")
    audit.permissions.append(
        PermissionFinding(
            category=PermissionCategory.DESTRUCTIVE,
            confidence=Confidence.HIGH,
            evidence=["delete"],
            tool_name="delete",
        )
    )
    assert report.model_copy().ux_summary == UxSummary(grade="D")
    audit.permissions = [
        PermissionFinding(
            category=PermissionCategory.NETWORK,
            confidence=Confidence.HIGH,
            evidence=["fetch"],
            tool_name="fetch",
        )
    ]
    assert report.model_copy().ux_summary == UxSummary(grade="B")
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="shell_wrapper_launch",
            severity=ConfigHealthSeverity.MEDIUM,
            server_name="example",
            summary="Shell wrapper launch",
            remediation="Review the shell arguments.",
        )
    ]
    assert report.ux_summary == UxSummary(grade="F")
    assert (audit.risk_score.model_dump() if audit.risk_score else None) == baseline
    payload = report.model_dump(mode="json")
    assert payload["ux_summary"] == UxSummary(grade="F").model_dump() and payload["schema_version"] == 1
    assert AuditReport.model_validate(payload).ux_summary == UxSummary(grade="F")


def test_hidden_instructions_and_chain_plus_shell_grade_classes() -> None:
    report = _summary_report("trifecta_report")
    audit = report.audits[0]
    audit.permissions = [
        PermissionFinding(
            category=PermissionCategory.SHELL_EXEC,
            confidence=Confidence.HIGH,
            evidence=["run"],
            tool_name="run",
        )
    ]
    assert report.model_copy().ux_summary.grade == "D"
    audit.permissions = []
    audit.capability_findings = [
        CapabilityFinding(
            target_type=CapabilityTarget.PROMPT,
            target_name="run",
            category=PermissionCategory.SHELL_EXEC,
            confidence=Confidence.HIGH,
            evidence=["run"],
        )
    ]
    assert report.model_copy().ux_summary.grade == "D"
    audit.injection_findings = _report_with_findings().audits[0].injection_findings
    assert report.ux_summary.grade == "F"


@pytest.mark.parametrize("state", ["not_run", "not_requested", "partial"])
def test_incomplete_metadata_has_preview_and_no_none_marker(state: str) -> None:
    report = _summary_report()
    report.coverage["metadata"] = CheckCoverage.model_validate({"state": state, "reason": "fixture limit"})
    html = _GEN.generate(report)
    assert report.ux_summary.grade is None
    assert "Preview" in html and 'aria-label="Grade ' not in html
    assert "None." not in html


def test_ssrf_and_egress_advice_deduplicates_but_log_keeps_both() -> None:
    report = _summary_report("ssrf_report")
    audit = report.audits[0]
    audit.ssrf_findings = [
        SsrfFinding(
            target_name="fetch",
            severity=SsrfSeverity.MEDIUM,
            pattern_name="url_param_with_fetch_verb",
            evidence=["caller URL"],
            description="Fetch any URL",
        )
    ]
    audit.egress_findings = [
        EgressFinding(
            target_name="fetch",
            severity=EgressSeverity.HIGH,
            kind=EgressKind.UNBOUNDED_EGRESS,
            evidence=["caller destination"],
        )
    ]
    merged = [action for action in actions(report) if action.title.startswith("Restrict where")]
    assert len(merged) == 1 and merged[0].severity == "high"
    assert len(merged[0].steps) == 2 and len(merged[0].sources) == 2
    html = _GEN.generate(report)
    assert "caller URL" in html and "caller destination" in html
    assert audit.ssrf_findings[0].rule_id in html and audit.egress_findings[0].rule_id in html


def test_hostname_is_scrubbed_everywhere_without_mutating_input() -> None:
    report = _summary_report()
    report.hostname = "synthetic-workstation"
    report.audits[0].connection_error = "Error on synthetic-workstation"
    html = _GEN.generate(report)
    assert "synthetic-workstation" not in html
    assert "synthetic-workstation" in _GEN.generate(report, show_host=True)
    assert report.audits[0].connection_error == "Error on synthetic-workstation"


@pytest.mark.parametrize("hostname", ["h", "high", "complete", "not_run", "skipped"])
def test_hostname_scrubbing_preserves_symbolic_fields(hostname: str) -> None:
    report = _summary_report()
    report.hostname = hostname
    report.audits[0].connection_error = f"Error on {hostname}"
    grade = report.ux_summary.grade
    assert grade is not None
    html = _GEN.generate(report)
    assert f"Error on {hostname}</p>" not in html
    assert f'aria-label="Grade {grade}"' in html
    assert "▲ Fix now" in html and "Checked:" in html


def test_hostname_collision_preserves_optional_literal_vocabulary() -> None:
    report = _summary_report()
    report.hostname = "IDENTITY_CONDITIONED_SURFACE"
    report.audits[0].drift_findings[0].kind = "IDENTITY_CONDITIONED_SURFACE"
    hidden = _hide_identifiers(report, report.hostname)
    assert isinstance(hidden, AuditReport)
    validated = AuditReport.model_validate(hidden.model_dump())
    assert validated.audits[0].drift_findings[0].kind == "IDENTITY_CONDITIONED_SURFACE"
    assert validated.hostname == "<redacted-host>"


@pytest.mark.parametrize("command", ["check", "scan"])
@pytest.mark.parametrize("show_host", [False, True])
def test_cli_html_show_host_option(
    tmp_path: Path, command: str, show_host: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("socket.gethostname", lambda: "synthetic-workstation")
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{"fixture":{"command":"synthetic-server"}}}')
    output = tmp_path / "report.html"
    args = [command, "--config", str(config), "--html", str(output)]
    if command == "scan":
        args += ["--config-only", "--skip-connect", "--override-config", "/dev/null"]
    if show_host:
        args.append("--show-host")
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert ("synthetic-workstation" in output.read_text()) == show_host


def _poison_strings(value: object, payload: str) -> object:
    if isinstance(value, BaseModel):
        updates = {
            name: _poison_strings(getattr(value, name), payload)
            for name, field in type(value).model_fields.items()
            if get_origin(field.annotation) is not Literal
        }
        return value.model_copy(update=updates)
    if isinstance(value, str) and not isinstance(value, Enum):
        return payload
    if isinstance(value, list):
        return [_poison_strings(item, payload) for item in value]
    if isinstance(value, tuple):
        return tuple(_poison_strings(item, payload) for item in value)
    if isinstance(value, dict):
        return {key: _poison_strings(item, payload) for key, item in value.items()}
    return value


@pytest.mark.parametrize(
    "payload",
    [
        '<script>alert("fixture")</script>',
        '<img src=x onerror="alert(1)">',
        '</summary><svg onload="alert(1)">',
        '"\'><iframe srcdoc="<script>1</script>">',
    ],
)
def test_model_wide_escape_fuzz(payload: str) -> None:
    for fixture in (
        "sample_audit_report",
        "config_only_report",
        "ssrf_report",
        "trifecta_report",
        "escalation_report",
        "provenance_report",
        "shadowing_report",
        "prompt_resource_report",
        "policy_failure_report",
        "failed_connection_report",
        "legacy_canary_report",
    ):
        report = AuditReport.model_validate_json(Path(f"tests/fixtures/reports/{fixture}.json").read_text())
        poisoned = _poison_strings(report, payload)
        assert isinstance(poisoned, AuditReport)
        for show_host in (False, True):
            html = _GEN.generate(poisoned, show_host=show_host)
            assert payload not in html, fixture
            assert "<script" not in html and "<img" not in html and "<svg" not in html
