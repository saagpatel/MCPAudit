"""SARIF coverage and extended config-health profile tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    ScanWarning,
)
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


def test_no_skip_compatibility_bytes_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mcp_audit.sarif.pkg_version", lambda _: "0.0.0")
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/config_only_report.json").read_text()
    )
    assert not any(warning.code == "review_source_skipped" for warning in report.warnings)
    output = json.dumps(SarifGenerator().generate(report), sort_keys=True).encode()
    # Captured from the compatibility renderer before source skips became results.
    assert sha256(output).hexdigest() == "0636a00191a2afa12cc3e02f219cd05e2fa869cd5af1dc97e8439d06a36cb58c"


def test_compatibility_emits_each_skip_but_not_unrelated_parse_failures(empty_report: AuditReport) -> None:
    for path, reason in (("/fixture/link.json", "symlink skipped"), ("/fixture/large.json", "byte limit")):
        empty_report.warnings.append(
            ScanWarning(code="review_source_skipped", message=f"Review source skipped: {path}: {reason}.")
        )
        empty_report.config_health_findings.append(
            ConfigHealthFinding(
                finding_type="config_parse_failure",
                severity=ConfigHealthSeverity.HIGH,
                summary=reason,
                remediation="Repair config.",
                config_paths=[path],
            )
        )
    empty_report.config_health_findings.append(
        ConfigHealthFinding(
            finding_type="config_parse_failure",
            severity=ConfigHealthSeverity.HIGH,
            summary="Malformed JSON.",
            remediation="Repair config.",
            config_paths=["/fixture/malformed.json"],
        )
    )
    run = SarifGenerator().generate(empty_report)["runs"][0]
    assert len(run["results"]) == 2
    assert {result["ruleId"] for result in run["results"]} == {"MCP-CH-CONFIG-PARSE-FAILURE"}
    assert all(result["level"] == "warning" for result in run["results"])
    assert all("--config FILE" in result["message"]["text"] for result in run["results"])
    assert [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]
    ] == [
        "file:///fixture/link.json",
        "file:///fixture/large.json",
    ]
    assert sum(rule["id"] == "MCP-CH-CONFIG-PARSE-FAILURE" for rule in run["tool"]["driver"]["rules"]) == 1


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
@pytest.mark.parametrize("skip_connect", [False, True])
@pytest.mark.parametrize("redaction_probe", [False, True])
async def test_project_connection_warning_reaches_sarif(
    profile: str, skip_connect: bool, redaction_probe: bool
) -> None:
    from mcp_audit.engine import ScanOptions, run_scan
    from tests.conftest import make_server_config

    args = ["--token", "synthetic-value"] if redaction_probe else ["--fixture"]
    server = make_server_config(command="synthetic-project-server", args=args)
    server.scope = "project"
    report = await run_scan(ScanOptions(skip_connect=skip_connect), servers=[server])
    warning = next(w for w in report.warnings if w.code == "project_config_not_connected")
    if redaction_probe:
        warning = warning.model_copy(
            update={
                # Report-level redaction treats a period touching a secret value as part of it.
                "message": (
                    f"Project config '{server.name}' not connected: synthetic-project-server --token "
                    "<redacted> Use --connect-project-configs to opt in (unless --skip-connect)."
                )
            }
        )
    # Coverage notifications must coexist with the exact, redacted skip explanation.
    run = SarifGenerator().generate(report, profile=profile)["runs"][0]
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    [notification] = [
        item for item in notifications if item["descriptor"]["id"] == "MCP-PROJECT-CONFIG-NOT-CONNECTED"
    ]
    assert notification["message"]["text"] == warning.message
    assert notification["properties"] == warning.model_dump()
    assert notification["level"] == "warning"
    assert "synthetic-value" not in notification["message"]["text"]
    if redaction_probe:
        assert "<redacted>" in notification["message"]["text"]
    assert any(item["descriptor"]["id"].startswith("MCP-COVERAGE-") for item in notifications)
