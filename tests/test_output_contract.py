"""Tests for documented output contract fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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


def test_prompt_resource_fixture_has_non_tool_risk_without_composite_change() -> None:
    fixture = Path("tests/fixtures/reports/prompt_resource_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    audit = report.audits[0]
    assert audit.risk_score is not None
    assert audit.risk_score.composite == 0.0
    assert audit.non_tool_risk is not None
    assert audit.non_tool_risk.composite > 0.0


def test_tool_findings_dump_target_metadata() -> None:
    fixture = Path("tests/fixtures/reports/sample_audit_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    dumped = report.model_dump(mode="json")
    first_permission = dumped["audits"][0]["permissions"][0]
    first_drift = dumped["audits"][0]["drift_findings"][0]
    assert first_permission["target_type"] == "tool"
    assert first_permission["target_name"] == first_permission["tool_name"]
    assert first_drift["target_type"] == "tool"
    assert first_drift["target_name"] == first_drift["tool_name"]


def test_output_contract_golden_snapshot() -> None:
    snapshot = {
        fixture.name: _fixture_signature(fixture) for fixture in sorted(FIXTURES, key=lambda path: path.name)
    }
    expected = json.loads(Path("tests/fixtures/reports/output_contract_snapshot.json").read_text())
    assert snapshot == expected


def _fixture_signature(fixture: Path) -> dict[str, Any]:
    report = AuditReport.model_validate_json(fixture.read_text())
    dumped = report.model_dump(mode="json")
    sarif = SarifGenerator().generate(report)
    return {
        "top_level_keys": sorted(dumped.keys()),
        "audit_count": len(dumped["audits"]),
        "audit_keys": sorted(dumped["audits"][0].keys()) if dumped["audits"] else [],
        "connection_statuses": [audit["connection_status"] for audit in dumped["audits"]],
        "permission_targets": _target_pairs(dumped, "permissions"),
        "capability_targets": _target_pairs(dumped, "capability_findings"),
        "injection_targets": _target_pairs(dumped, "injection_findings"),
        "drift_targets": _target_pairs(dumped, "drift_findings"),
        "sarif_rule_ids": sorted({result["ruleId"] for result in sarif["runs"][0]["results"]}),
        "sarif_target_types": sorted(
            {
                result.get("properties", {}).get("target_type")
                for result in sarif["runs"][0]["results"]
                if result.get("properties", {}).get("target_type")
            }
        ),
    }


def _target_pairs(dumped_report: dict[str, Any], key: str) -> list[list[str | None]]:
    return [
        list(pair)
        for pair in sorted(
            {
                (finding.get("target_type"), finding.get("target_name"))
                for audit in dumped_report["audits"]
                for finding in audit.get(key, [])
            }
        )
    ]
