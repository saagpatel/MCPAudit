"""Tests for documented output contract fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_audit.models import AuditReport, ConnectionMode
from mcp_audit.sarif import SarifGenerator

FIXTURES = [
    Path("tests/fixtures/reports/sample_audit_report.json"),
    Path("tests/fixtures/reports/failed_connection_report.json"),
    Path("tests/fixtures/reports/config_only_report.json"),
    Path("tests/fixtures/reports/policy_failure_report.json"),
    Path("tests/fixtures/reports/prompt_resource_report.json"),
    Path("tests/fixtures/reports/ssrf_report.json"),
    Path("tests/fixtures/reports/trifecta_report.json"),
    Path("tests/fixtures/reports/shadowing_report.json"),
    Path("tests/fixtures/reports/escalation_report.json"),
    Path("tests/fixtures/reports/provenance_report.json"),
]
LEGACY_FIXTURES = sorted(Path("tests/fixtures/reports/legacy").glob("*.json"))
FIELD_REPORT_FIXTURES = sorted(Path("tests/fixtures/reports/field").glob("*.json"))


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


def test_config_only_fixture_includes_structured_config_health() -> None:
    fixture = Path("tests/fixtures/reports/config_only_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    dumped = report.model_dump(mode="json")
    finding = dumped["config_health_findings"][0]
    assert finding["finding_type"] == "remote_endpoint"
    assert finding["server_name"] == "remote-api"
    assert finding["severity"] == "medium"


def test_trifecta_fixture_loads_and_generates_mcp013() -> None:
    fixture = Path("tests/fixtures/reports/trifecta_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.audits[0].trifecta_findings
    assert report.audits[0].trifecta_findings[0].severity.value == "high"
    sarif = SarifGenerator().generate(report)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "MCP013" in rule_ids
    dumped = report.model_dump(mode="json")
    assert "trifecta_findings" in dumped["audits"][0]
    assert "fleet_trifecta_findings" in dumped


def test_shadowing_fixture_loads_and_generates_mcp015() -> None:
    fixture = Path("tests/fixtures/reports/shadowing_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.shadowing_findings
    assert report.shadowing_findings[0].kind.value == "exact"
    sarif = SarifGenerator().generate(report)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "MCP015" in rule_ids
    dumped = report.model_dump(mode="json")
    assert "shadowing_findings" in dumped


def test_escalation_fixture_loads_and_generates_mcp018() -> None:
    fixture = Path("tests/fixtures/reports/escalation_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.audits[0].escalation_findings
    finding = report.audits[0].escalation_findings[0]
    assert finding.kind.value == "capability"
    assert finding.severity.value == "high"
    assert finding.rule_id == "MCP018"
    sarif = SarifGenerator().generate(report)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "MCP018" in rule_ids
    dumped = report.model_dump(mode="json")
    assert "escalation_findings" in dumped["audits"][0]


def test_provenance_fixture_loads_and_generates_mcp021() -> None:
    fixture = Path("tests/fixtures/reports/provenance_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    assert report.audits[0].provenance_findings
    finding = report.audits[0].provenance_findings[0]
    assert finding.kind.value == "args"
    assert finding.severity.value == "high"
    assert finding.rule_id == "MCP021"
    assert "--no-sandbox" in finding.gained_flags
    sarif = SarifGenerator().generate(report)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "MCP021" in rule_ids
    dumped = report.model_dump(mode="json")
    assert "provenance_findings" in dumped["audits"][0]


def test_output_contract_golden_snapshot() -> None:
    snapshot = {
        fixture.name: _fixture_signature(fixture) for fixture in sorted(FIXTURES, key=lambda path: path.name)
    }
    expected = json.loads(Path("tests/fixtures/reports/output_contract_snapshot.json").read_text())
    assert snapshot == expected


def test_legacy_reports_load_through_current_model() -> None:
    assert LEGACY_FIXTURES
    for fixture in LEGACY_FIXTURES:
        report = AuditReport.model_validate_json(fixture.read_text())
        dumped = report.model_dump(mode="json")
        assert report.scan_timestamp
        assert report.connection_mode is ConnectionMode.UNKNOWN
        assert "config_health_findings" in dumped
        assert "policy_result" in dumped
        for audit in report.audits:
            assert isinstance(audit.capability_findings, list)
            assert isinstance(audit.injection_findings, list)
            assert isinstance(audit.drift_findings, list)


def test_field_report_fixtures_load_through_current_model() -> None:
    assert FIELD_REPORT_FIXTURES
    for fixture in FIELD_REPORT_FIXTURES:
        report = AuditReport.model_validate_json(fixture.read_text())
        dumped = report.model_dump(mode="json")
        assert report.servers_discovered == len(report.audits)
        assert "config_health_findings" in dumped
        assert all("server" in audit for audit in dumped["audits"])
        assert "Bearer " not in fixture.read_text()
        assert "sk-" not in fixture.read_text()


def test_future_additive_report_fields_are_ignored() -> None:
    fixture = Path("tests/fixtures/reports/legacy/future_additive_report.json")
    report = AuditReport.model_validate_json(fixture.read_text())
    dumped = report.model_dump(mode="json")

    assert "future_report_field" not in dumped
    assert "future_audit_field" not in dumped["audits"][0]
    assert "future_server_field" not in dumped["audits"][0]["server"]
    assert "future_finding_field" not in dumped["audits"][0]["permissions"][0]


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
        "ssrf_targets": _target_pairs(dumped, "ssrf_findings"),
        "trifecta_findings_count": sum(len(audit.get("trifecta_findings", [])) for audit in dumped["audits"]),
        "fleet_trifecta_findings_count": len(dumped.get("fleet_trifecta_findings", [])),
        "shadowing_findings_count": len(dumped.get("shadowing_findings", [])),
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
