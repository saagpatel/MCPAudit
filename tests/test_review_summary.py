"""Every summary input keeps its pre-redaction decisions through all output paths."""

import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError
from rich.console import Console

from mcp_audit import ux_summary
from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ConnectionMode,
    EgressFinding,
    PolicyResult,
    PolicyViolation,
    ReviewSummary,
    ScanWarning,
    ShadowingFinding,
    ShadowingKind,
    ShadowingSeverity,
    TrifectaFinding,
    UxSummary,
)
from mcp_audit.report import ReportGenerator
from mcp_audit.terminal_summary import findings, grade

# Each audit case is isolated so a missing source cannot hide behind other actions.
_COMMON = {"server_name": "shared-server", "severity": "high"}
_PACKAGE = {
    **_COMMON,
    "ecosystem": "npm",
    "package": "toy",
    "version": "1",
    "baseline_hash": "a" * 64,
    "current_hash": "b" * 64,
    "summary": "Changed",
}
_CASES: dict[str, dict[str, object]] = {
    "permissions": {
        "category": "shell_execution",
        "confidence": "high",
        "tool_name": "run",
        "evidence": ["run"],
    },
    "capability_findings": {
        "category": "shell_execution",
        "confidence": "high",
        "target_type": "prompt",
        "target_name": "run",
        "evidence": ["run"],
    },
    "injection_findings": {
        "severity": "high",
        "tool_name": "run",
        "pattern_name": "override",
        "matched_text": "ignore",
        "description": "Synthetic instruction",
    },
    "ssrf_findings": {
        "severity": "high",
        "target_name": "fetch",
        "pattern_name": "url_param",
        "evidence": ["url"],
        "description": "Synthetic outbound",
    },
    "egress_findings": {
        "severity": "high",
        "target_name": "fetch",
        "kind": "unbounded_egress",
        "evidence": ["url"],
    },
    "annotation_findings": {
        "severity": "high",
        "tool_name": "run",
        "hint": "readOnlyHint",
        "declared_value": True,
        "category": "shell_execution",
        "confidence": "high",
        "evidence": ["run"],
    },
    "trifecta_findings": {
        "severity": "high",
        "leg1_contributors": [("shared-server", "read")],
        "leg2_contributors": [("shared-server", "fetch")],
        "leg3_contributors": [("shared-server", "send")],
        "description": "Synthetic chain",
    },
    "escalation_findings": {**_COMMON, "kind": "capability", "tool_name": "run", "description": "Changed"},
    "provenance_findings": {
        **_COMMON,
        "kind": "command",
        "summary": "Changed",
        "baseline": "before",
        "current": "after",
    },
    "integrity_findings": {
        **_COMMON,
        "kind": "artifact_drift",
        "artifact_path": "/tmp/toy",
        "baseline_hash": "a" * 64,
        "current_hash": "b" * 64,
        "summary": "Changed",
    },
    "package_verify_findings": {**_PACKAGE, "kind": "registry_drift"},
    "artifact_verify_findings": {**_PACKAGE, "kind": "baseline_mismatch"},
    "drift_findings": {
        **_COMMON,
        "tool_name": "run",
        "status": "changed",
        "remediation": "Review changed metadata.",
    },
}
_SOURCES = [*_CASES, "annotations_missing", "config_health", "policy", "fleet", "shadowing", "all"]


def _report(source: str, home: str, count: int) -> AuditReport:
    audit_rows: list[dict[str, object]] = []
    health_rows: list[dict[str, object]] = []
    for index in range(count):
        path = f"{home}/synthetic-user-{index}/mcp.json"
        row: dict[str, object] = {
            "server": {
                "name": "shared-server",
                "client": "claude_code",
                "config_path": path,
                "transport": "stdio",
            },
            "connection_status": "connected",
        }
        for field, finding in _CASES.items():
            if source in {field, "all"}:
                row[field] = [finding]
        if source in {"annotations_missing", "all"}:
            row["annotations_missing"] = True
        audit_rows.append(row)
        if source in {"config_health", "all"}:
            health_rows.append(
                {
                    "finding_type": "synthetic_config_warning",
                    "severity": "high",
                    "server_name": "shared-server",
                    "summary": f"Review config at {path} on synthetic-host",
                    "config_paths": [path],
                    "remediation": "Review this config.",
                }
            )
    report = AuditReport(
        scan_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        hostname="synthetic-host",
        os_platform="synthetic",
        connection_mode=ConnectionMode.ATTEMPTED,
        servers_discovered=count,
        servers_connected=count,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[],
        scan_duration_seconds=0,
        coverage={
            **{
                key: CheckCoverage(state="not_requested", reason="check not requested")
                for key in OPTIONAL_CHECKS
            },
            **{
                key: CheckCoverage(state="complete", reason="Synthetic check")
                for key in ("config_health", "metadata", "permissions", "capabilities")
            },
        },
    )
    # Validate all synthetic finding shapes through the actual report model.
    data = {field: getattr(report, field) for field in AuditReport.model_fields}
    data.update(audits=audit_rows, config_health_findings=health_rows)
    report = AuditReport.model_validate(data)
    if source in {"policy", "all"}:
        report.policy_result = PolicyResult(
            passed=False,
            violations=[
                PolicyViolation(
                    rule="synthetic",
                    message="Review synthetic policy",
                    server_name="shared-server",
                    tool_name=f"{home}/synthetic-user-{index}/target",
                    audit_index=index,
                )
                for index in range(count)
            ],
        )
    if source in {"fleet", "all"}:
        data = dict(_CASES["trifecta_findings"], severity="medium", is_fleet=True)
        report.fleet_trifecta_findings = [TrifectaFinding.model_validate(data)]
    if source in {"shadowing", "all"}:
        report.shadowing_findings = [
            ShadowingFinding(
                kind=ShadowingKind.EXACT,
                severity=ShadowingSeverity.HIGH,
                name="run",
                collisions=[("shared-server", "run")],
                description="Collision",
            )
        ]
    return report


@pytest.mark.parametrize("source", _SOURCES)
@pytest.mark.parametrize("home,count", [("/Users", 2), ("/home", 3)])
def test_every_source_survives_redaction_and_roundtrip(source: str, home: str, count: int) -> None:
    report = _report(source, home, count)
    baseline = report.ensure_review_summary()
    expected_count = 1 if source in {"fleet", "shadowing"} else count
    if source != "all":
        assert baseline.action_count == expected_count
    if source == "config_health":
        assert baseline.grade == "D"  # The round-three D -> C regression.
    credential_redacted = report.redacted()
    redacted = report.redacted(identifiers=True)
    twice = redacted.redacted(identifiers=True)
    restored = AuditReport.model_validate_json(redacted.model_dump_json())
    credential_restored = AuditReport.model_validate_json(credential_redacted.model_dump_json())
    for candidate in (
        report,
        credential_redacted,
        credential_redacted.redacted(),
        credential_restored,
        redacted,
        redacted.redacted(),
        twice,
        restored,
    ):
        summary = candidate.ensure_review_summary()
        assert summary.action_count == baseline.action_count
        assert summary.action_counts == baseline.action_counts
        assert summary.grade == baseline.grade
        assert summary.review_minutes == baseline.review_minutes
        assert [(a.identity, a.owner, a.severity) for a in summary.actions] == [
            (a.identity, a.owner, a.severity) for a in baseline.actions
        ]
        assert [a.card_group for a in summary.actions] == [a.card_group for a in baseline.actions]
        for show_host in (False, True):
            html = HtmlReportGenerator().generate(candidate, show_host=show_host)
            assert html.count('<article class="action">') == baseline.action_count
            assert f"Estimated initial review: {baseline.review_minutes} minutes" in html
            assert f'aria-label="Grade {baseline.grade}"' in html
            for severity, label in (("high", "Top fixes"), ("medium", "Worth a look"), ("low", "FYI")):
                assert f"{label} · {baseline.action_counts[severity]}" in html
            if candidate in (redacted, twice, restored):
                for identifier in ("synthetic-user-", "synthetic-host", "shared-server"):
                    assert identifier not in html + candidate.model_dump_json()
        terminal = StringIO()
        ReportGenerator(Console(file=terminal, width=180)).render_terminal(candidate, details=False)
        assert grade(candidate) == baseline.grade
        assert len(findings(candidate)) == baseline.action_count
        assert f"Totals: {baseline.action_count} findings" in terminal.getvalue()
        assert f"Estimated initial review: {baseline.review_minutes} minutes" in terminal.getvalue()
        assert f"MCPAudit · Grade {baseline.grade}" in terminal.getvalue()
    assert twice.review_summary == redacted.review_summary == restored.review_summary


def test_summary_computed_once_even_across_renderers_and_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _report("all", "/Users", 2)
    repr(report)  # Debugging must not freeze a report before policy is attached.
    assert report.review_summary is None
    original = ux_summary.compute_summary
    calls = 0

    def counted(candidate: AuditReport) -> ReviewSummary:
        nonlocal calls
        calls += 1
        return original(candidate)

    monkeypatch.setattr(ux_summary, "compute_summary", counted)
    HtmlReportGenerator().generate(report)
    redacted = report.redacted(identifiers=True).redacted(identifiers=True)
    reloaded = AuditReport.model_validate_json(redacted.model_dump_json())
    HtmlReportGenerator().generate(reloaded)
    ReportGenerator(Console(file=StringIO())).render_terminal(reloaded)
    ReportGenerator(Console(file=StringIO())).render_terminal(reloaded, details=False)
    assert ux_summary.actions(reloaded) == reloaded.ensure_review_summary().actions
    assert ux_summary.grade(reloaded) == report.ux_summary.grade
    assert calls == 1


def test_credential_redaction_cannot_collapse_config_identities() -> None:
    report = _report("permissions", "/Users", 2)
    for index, audit in enumerate(report.audits):
        audit.server.config_path = f"https://fixture.example/mcp.json?token=synthetic-secret-{index}"
    redacted = report.redacted()
    assert redacted.audits[0].server.config_path == redacted.audits[1].server.config_path
    assert redacted.ensure_review_summary().action_count == 2
    assert redacted.ux_summary == UxSummary(grade="D")
    terminal = StringIO()
    ReportGenerator(Console(file=terminal, width=180)).render_terminal(redacted, details=False)
    assert "1. ▲ Fix now" in terminal.getvalue() and "2. ▲ Fix now" in terminal.getvalue()
    assert "synthetic-secret-" not in redacted.model_dump_json()


def test_grade_counts_distinct_findings_before_shared_advice_is_grouped() -> None:
    report = _report("ssrf_findings", "/Users", 1)
    audit = report.audits[0]
    audit.egress_findings = [EgressFinding.model_validate(_CASES["egress_findings"])]
    baseline = report.ensure_review_summary()
    assert baseline.action_count == 1  # One target, two independent finding classes.
    assert baseline.grade == "D"
    redacted = report.redacted(identifiers=True)
    for candidate in (
        report,
        report.redacted(),
        redacted,
        redacted.redacted(identifiers=True),
        AuditReport.model_validate_json(redacted.model_dump_json()),
    ):
        summary = candidate.ensure_review_summary()
        assert (summary.grade, summary.action_count, summary.review_minutes) == ("D", 1, 5)
        assert candidate.ux_summary.grade == "D"
        assert json.loads(candidate.model_dump_json())["ux_summary"]["grade"] == "D"
        for show_host in (False, True):
            assert 'aria-label="Grade D"' in HtmlReportGenerator().generate(candidate, show_host=show_host)
        terminal = StringIO()
        ReportGenerator(Console(file=terminal, width=180)).render_terminal(candidate, details=False)
        assert "MCPAudit · Grade D" in terminal.getvalue()


def test_large_alias_set_keeps_summary_display_idempotent() -> None:
    report = _report("permissions", "/Users", 101)
    for index, audit in enumerate(report.audits):
        audit.server.name = f"synthetic-server-{index}"
    redacted = report.redacted(identifiers=True)
    assert redacted.redacted(identifiers=True).review_summary == redacted.review_summary


def test_terminal_warning_card_preserves_degraded_coverage() -> None:
    report = _report("permissions", "/Users", 2)
    report.warnings = [ScanWarning(code="synthetic_incomplete", message="Synthetic coverage unavailable.")]
    terminal = StringIO()
    ReportGenerator(Console(file=terminal, width=180)).render_terminal(report, details=False)
    assert report.ensure_review_summary().grade is None
    assert "MCPAudit · Preview" in terminal.getvalue()
    assert "Restore check coverage" in terminal.getvalue()
    assert "2 findings (2 Fix now" in terminal.getvalue()


@pytest.mark.parametrize("field", ["grade", "identity", "owner", "card_group"])
def test_saved_summary_rejects_untrusted_symbolic_values(field: str) -> None:
    payload = _report("permissions", "/Users", 2).model_dump(mode="json")
    summary = payload["review_summary"]
    target = summary if field == "grade" else summary["actions"][0]
    target[field] = "<script>synthetic</script>"
    with pytest.raises(ValidationError):
        AuditReport.model_validate(payload)


@pytest.mark.parametrize("show_host", [False, True])
def test_real_config_only_cli_redaction_keeps_summary(tmp_path: Path, show_host: bool) -> None:
    from mcp_audit import cli

    config = tmp_path / "synthetic-config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    name: {"command": "sh", "args": ["-c", f"cat /Users/synthetic-user-{index}/data"]}
                    for index, name in enumerate(("toy-a", "toy-b"))
                }
            }
        )
    )
    summaries = []
    for redact in (False, True):
        output = tmp_path / f"report-{redact}.json"
        html_output = tmp_path / f"report-{redact}.html"
        args = [
            "scan",
            "--config",
            str(config),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--json",
            str(output),
            "--html",
            str(html_output),
        ]
        if show_host:
            args.append("--show-host")
        if redact:
            args.append("--redact")
        result = CliRunner().invoke(cli.main, args)
        assert result.exit_code == 0, result.output
        report = AuditReport.model_validate_json(output.read_text())
        summary = report.ensure_review_summary()
        summaries.append(summary)
        html = html_output.read_text()
        assert "Preview" in html  # Config-only scans never manufacture a grade.
        assert html.count('<article class="action">') == summary.action_count
        assert f"Estimated initial review: {summary.review_minutes} minutes" in html
        if redact:
            assert "synthetic-user-" not in html + output.read_text()
    assert summaries[0].grade == summaries[1].grade is None
    assert summaries[0].action_count == summaries[1].action_count >= 2
    assert summaries[0].action_counts == summaries[1].action_counts


@pytest.mark.parametrize("show_host", [False, True])
def test_cli_connected_fixture_preserves_config_health_grade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    show_host: bool,
) -> None:
    from mcp_audit import cli

    # Inject completed synthetic metadata; no server is launched or contacted.
    report = _report("config_health", "/Users", 2)

    async def fake_run_scan(*args: object, **kwargs: object) -> AuditReport:
        return report

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    config = tmp_path / "config.json"
    config.write_text('{"mcpServers":{"fixture":{"command":"synthetic-server"}}}')
    for redact in (False, True):
        html_path = tmp_path / f"report-{redact}.html"
        json_path = tmp_path / f"report-{redact}.json"
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
        if redact:
            args.append("--redact")
        if show_host:
            args.append("--show-host")
        result = CliRunner().invoke(cli.main, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(json_path.read_text())
        assert payload["ux_summary"] == UxSummary(grade="D").model_dump()
        assert payload["review_summary"]["action_count"] == 2
        html = html_path.read_text()
        assert 'aria-label="Grade D"' in html
        assert "Top fixes · 2" in html and "Estimated initial review: 10 minutes" in html
        if redact:
            for identifier in ("synthetic-user-", "synthetic-host", "shared-server"):
                assert identifier not in html + json_path.read_text()
