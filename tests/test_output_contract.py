"""Tests for documented output contract fixtures."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.models import AuditReport
from mcp_audit.sarif import SarifGenerator


def test_sample_json_report_matches_current_model() -> None:
    fixture = Path("tests/fixtures/reports/sample_audit_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.audits[0].capability_findings[0].target_type == "resource"
    assert report.policy_result is not None
    assert not report.policy_result.passed


def test_sample_json_report_generates_sarif_contract_rules() -> None:
    fixture = Path("tests/fixtures/reports/sample_audit_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    sarif = SarifGenerator().generate(report)
    rule_ids = {result["ruleId"] for result in sarif["runs"][0]["results"]}
    assert "MCP009" in rule_ids
    assert "MCP010" in rule_ids
