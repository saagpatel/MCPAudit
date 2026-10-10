"""Regression coverage for identity-preserving HTML display redaction."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit import cli
from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ClientType,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
    ServerConfig,
    TransportType,
    UxSummary,
)
from mcp_audit.ux_summary import actions


@pytest.fixture
def identity_report(request: pytest.FixtureRequest) -> AuditReport:
    home_root = request.param
    assert isinstance(home_root, str)
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    for key in ("config_health", "metadata", "permissions", "capabilities"):
        report.coverage[key] = CheckCoverage(state="complete", reason="synthetic fixture check completed")
    for key in OPTIONAL_CHECKS:
        report.coverage.setdefault(key, CheckCoverage(state="not_requested", reason="check not requested"))
    report.audits = [
        ServerAudit(
            server=ServerConfig(
                name="shared-server",
                client=ClientType.CLAUDE_CODE,
                config_path=f"{home_root}/{user}/mcp.json",
                transport=TransportType.STDIO,
            ),
            connection_status="connected",
            permissions=[
                PermissionFinding(
                    category=PermissionCategory.SHELL_EXEC,
                    confidence=Confidence.HIGH,
                    evidence=["run"],
                    tool_name="run",
                )
            ],
        )
        for user in ("synthetic-user-a", "synthetic-user-b")
    ]
    report.config_health_findings = []
    report.fleet_trifecta_findings = []
    report.shadowing_findings = []
    report.policy_result = None
    report.servers_discovered = report.servers_connected = 2
    report.total_tools = report.high_risk_servers = 0
    return report


@pytest.mark.parametrize("identity_report", ["/Users", "/home"], indirect=True)
def test_identifier_redaction_preserves_action_identity_and_grade(identity_report: AuditReport) -> None:
    report = identity_report
    home_root = report.audits[0].server.config_path.split("/", 2)[1]
    original = report.model_dump(mode="json")
    assert len(actions(report)) == 2
    assert report.ux_summary.grade == "D"

    for show_host in (False, True):
        html = HtmlReportGenerator().generate(report, show_host=show_host)
        assert 'aria-label="Grade D"' in html
        assert "Top fixes · 2" in html
        assert html.count('<article class="action">') == 2
        assert "2 actions need your review before use." in html
        assert "Estimated initial review: 10 minutes" in html
        for user in ("synthetic-user-a", "synthetic-user-b"):
            assert (f"/{home_root}/{user}/mcp.json" in html) == show_host
        if not show_host:
            assert (
                html.count(f"MCP004: shared-server (claude_code, /{home_root}/&lt;redacted&gt;/mcp.json)")
                == 2
            )
    assert report.model_dump(mode="json") == original


@pytest.mark.parametrize("identity_report", ["/Users", "/home"], indirect=True)
def test_repeated_redaction_preserves_grouping_and_json_grade(identity_report: AuditReport) -> None:
    original = identity_report.model_dump(mode="json")
    redacted = identity_report.redacted(identifiers=True)
    for candidate in (redacted, redacted.redacted(), redacted.redacted(identifiers=True)):
        assert len(actions(candidate)) == 2
        assert candidate.ux_summary == UxSummary(grade="D")
        payload = candidate.model_dump(mode="json")
        assert payload["ux_summary"] == UxSummary(grade="D").model_dump()
        assert payload["schema_version"] == 1
        restored = AuditReport.model_validate(payload)
        assert restored.ux_summary == UxSummary(grade="D")
        assert len(actions(restored)) == 2
        shared = json.dumps(payload) + repr(actions(candidate))
        assert "synthetic-user" not in shared
        assert "shared-server" not in shared
    assert identity_report.model_dump(mode="json") == original


@pytest.mark.parametrize("identity_report", ["/Users", "/home"], indirect=True)
def test_redacted_summary_is_a_snapshot_after_findings_change(identity_report: AuditReport) -> None:
    redacted = identity_report.redacted(identifiers=True)
    summary = redacted.ensure_review_summary().model_dump()
    redacted.audits[0].permissions = []
    redacted.audits[1].permissions = []
    assert redacted.ux_summary == UxSummary(grade="D")
    assert redacted.ensure_review_summary().model_dump() == summary
    assert "Top fixes · 2" in HtmlReportGenerator().generate(redacted)


@pytest.mark.parametrize("identity_report", ["/Users", "/home"], indirect=True)
def test_redaction_preserves_deduplication_for_one_identity(identity_report: AuditReport) -> None:
    report = identity_report
    report.audits[1].server = report.audits[0].server.model_copy(deep=True)
    assert len(actions(report)) == 1
    redacted = report.redacted(identifiers=True)
    assert len(actions(redacted)) == 1
    assert redacted.ux_summary == UxSummary(grade="C")
    assert redacted.audits[0].presentation_id == redacted.audits[1].presentation_id


@pytest.mark.parametrize("identity_report", ["/Users", "/home"], indirect=True)
@pytest.mark.parametrize("show_host", [False, True])
@pytest.mark.parametrize("redact", [False, True])
def test_scan_redaction_preserves_html_actions_and_json_grade(
    identity_report: AuditReport,
    show_host: bool,
    redact: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def fake_run_scan(*args: object, **kwargs: object) -> AuditReport:
        return identity_report

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{"fixture":{"command":"synthetic-server"}}}')
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"
    args = [
        "scan",
        "--config",
        str(config),
        "--config-only",
        "--skip-connect",
        "--override-config",
        "/dev/null",
        "--html",
        str(html_path),
        "--json",
        str(json_path),
    ]
    if show_host:
        args.append("--show-host")
    if redact:
        args.append("--redact")
    original = identity_report.model_dump(mode="json")
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 0, result.output
    html = html_path.read_text()
    assert 'aria-label="Grade D"' in html
    assert "Top fixes · 2" in html
    assert html.count('<article class="action">') == 2
    assert "2 actions need your review before use." in html
    assert "Estimated initial review: 10 minutes" in html
    text = json_path.read_text()
    payload = json.loads(text)
    assert payload["ux_summary"] == UxSummary(grade="D").model_dump()
    assert payload["schema_version"] == 1
    assert len(payload["audits"]) == 2
    assert AuditReport.model_validate(payload).ux_summary == UxSummary(grade="D")
    for identifier in ("synthetic-user-a", "synthetic-user-b", "shared-server"):
        assert (identifier in text) == (not redact)
    if redact:
        for identifier in ("synthetic-user-a", "synthetic-user-b", "shared-server", identity_report.hostname):
            assert identifier not in html
    assert identity_report.model_dump(mode="json") == original


def test_default_html_hides_explicit_config_home_paths() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    for audit in report.audits:
        audit.server.config_path = "/Users/synthetic-user/claude_desktop_config.json"
        audit.server.config_source = "explicit file; parsed as Claude-style config"
    hidden = HtmlReportGenerator().generate(report)
    assert "synthetic-user" not in hidden
    assert "explicit file; parsed as Claude-style config" in hidden
    assert "synthetic-user" in HtmlReportGenerator().generate(report, show_host=True)
