"""Tests for documented output contract fixtures."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.models import AuditReport
from mcp_audit.sarif import SarifGenerator

FIXTURES = [
    Path("tests/fixtures/reports/sample_audit_report.json"),
    Path("tests/fixtures/reports/failed_connection_report.json"),
    Path("tests/fixtures/reports/config_only_report.json"),
    Path("tests/fixtures/reports/policy_failure_report.json"),
    Path("tests/fixtures/reports/prompt_resource_report.json"),
]


def test_sample_json_report_matches_current_model() -> None:
    fixture = Path("tests/fixtures/reports/sample_audit_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.audits[0].capability_findings[0].target_type == "resource"
    assert report.policy_result is not None
    assert not report.policy_result.passed


def test_contract_fixtures_match_current_model() -> None:
    for fixture in FIXTURES:
        report = AuditReport.model_validate_json(fixture.read_text())
        assert report.scan_timestamp


def test_sample_json_report_generates_sarif_contract_rules() -> None:
    fixture = Path("tests/fixtures/reports/sample_audit_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    sarif = SarifGenerator().generate(report)
    rule_ids = {result["ruleId"] for result in sarif["runs"][0]["results"]}
    assert "MCP009" in rule_ids
    assert "MCP010" in rule_ids


def test_prompt_resource_fixture_generates_target_metadata() -> None:
    fixture = Path("tests/fixtures/reports/prompt_resource_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    sarif = SarifGenerator().generate(report)
    results = sarif["runs"][0]["results"]
    assert any(result["properties"].get("target_type") == "prompt" for result in results)
    assert any(result["properties"].get("target_type") == "resource" for result in results)
