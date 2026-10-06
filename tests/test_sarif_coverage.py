"""SARIF coverage and extended config-health profile tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mcp_audit.models import AuditReport, CheckCoverage, ConfigHealthFinding, ConfigHealthSeverity
from mcp_audit.sarif import SarifGenerator


@pytest.fixture
def empty_report() -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="fixture-host",
        os_platform="Darwin",
        servers_discovered=0,
        servers_connected=0,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[],
        scan_duration_seconds=0.0,
    )


@pytest.fixture
def config_health_report(empty_report: AuditReport) -> AuditReport:
    empty_report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="duplicate_server_name",
            severity=ConfigHealthSeverity.MEDIUM,
            server_name="fixture-server",
            summary="A duplicate server name was found.",
            details=["Two synthetic configs use the same name."],
            remediation="Rename one synthetic server entry.",
        )
    ]
    return empty_report


def test_legacy_report_has_unknown_coverage_notification(empty_report: AuditReport) -> None:
    sarif = SarifGenerator().generate(empty_report)
    run = sarif["runs"][0]

    assert run["properties"]["mcpAuditCoverage"] == {}
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["toolExecutionNotifications"] == [
        {
            "level": "warning",
            "message": {"text": "Coverage is unknown because this report predates coverage tracking."},
            "descriptor": {"id": "MCP-COVERAGE-UNKNOWN"},
        }
    ]


def test_partial_and_not_run_checks_are_properties_and_notifications(
    empty_report: AuditReport,
) -> None:
    empty_report.coverage = {
        "permissions": CheckCoverage(state="partial", reason="pagination limit reached"),
        "runtime_security": CheckCoverage(state="not_run", reason="connections disabled"),
        "metadata": CheckCoverage(state="complete", reason=""),
        "llm_analysis": CheckCoverage(state="not_requested", reason="disabled by user"),
    }
    run = SarifGenerator().generate(empty_report)["runs"][0]

    assert run["properties"]["mcpAuditCoverage"] == {
        "permissions": {"state": "partial", "reason": "pagination limit reached"},
        "runtime_security": {"state": "not_run", "reason": "connections disabled"},
        "metadata": {"state": "complete", "reason": ""},
        "llm_analysis": {"state": "not_requested", "reason": "disabled by user"},
    }
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert [item["descriptor"]["id"] for item in notifications] == [
        "MCP-COVERAGE-UNKNOWN",
        "MCP-COVERAGE-PARTIAL",
        "MCP-COVERAGE-NOT_RUN",
    ]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sparse_coverage_reports_missing_checks_as_unknown(empty_report: AuditReport) -> None:
    empty_report.coverage = {
        "permissions": CheckCoverage(state="complete", reason="completed for all configured servers")
    }

    run = SarifGenerator().generate(empty_report)["runs"][0]
    notifications = run["invocations"][0]["toolExecutionNotifications"]

    assert notifications[0] == {
        "level": "warning",
        "message": {
            "text": (
                "Coverage is unknown for checks with no recorded state: config_health, capabilities, "
                "metadata, inject_check, ssrf_check, egress_check, pin_check, trifecta_check, "
                "shadow_check, escalation_check, provenance_check, integrity_check, verify_artifacts, "
                "download_artifacts, llm_analysis, runtime_security."
            )
        },
        "descriptor": {"id": "MCP-COVERAGE-UNKNOWN"},
    }
    assert len(notifications) == 1


def test_compatibility_profile_omits_config_health_findings(
    config_health_report: AuditReport,
) -> None:
    sarif = SarifGenerator().generate(config_health_report)
    run = sarif["runs"][0]

    assert run["results"] == []
    assert all(not rule["id"].startswith("MCP-CH-") for rule in run["tool"]["driver"]["rules"])


def test_extended_profile_emits_stable_config_health_rule_and_result(
    config_health_report: AuditReport,
) -> None:
    sarif = SarifGenerator().generate(config_health_report, profile="extended")
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]

    assert "MCP-CH-DUPLICATE-SERVER-NAME" in {rule["id"] for rule in rules}
    result = run["results"][0]
    assert result["ruleId"] == "MCP-CH-DUPLICATE-SERVER-NAME"
    assert result["level"] == "warning"
    assert result["properties"]["finding_type"] == "duplicate_server_name"
    assert result["properties"]["remediation"] == "Rename one synthetic server entry."


def test_unknown_profile_is_rejected(empty_report: AuditReport) -> None:
    with pytest.raises(ValueError, match="Unknown SARIF profile"):
        SarifGenerator().generate(empty_report, profile="unknown")


@pytest.mark.anyio
@pytest.mark.parametrize("profile", ["compatibility", "extended"])
async def test_project_connection_warning_reaches_sarif(profile: str) -> None:
    from mcp_audit.engine import ScanOptions, run_scan
    from tests.conftest import make_server_config

    server = make_server_config(command="synthetic-project-server", args=["--fixture"])
    server.scope = "project"
    report = await run_scan(ScanOptions(), servers=[server])
    warning = next(w for w in report.warnings if w.code == "project_config_not_connected")
    # Coverage notifications must coexist with the exact, redacted skip explanation.
    run = SarifGenerator().generate(report, profile=profile)["runs"][0]
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    notification = next(
        item for item in notifications if item["descriptor"]["id"] == "MCP-PROJECT-CONFIG-NOT-CONNECTED"
    )
    assert notification["message"]["text"] == warning.message
    assert notification["properties"] == warning.model_dump()
    assert notification["level"] == "warning"
    assert any(item["descriptor"]["id"].startswith("MCP-COVERAGE-") for item in notifications)
