"""Fixture-backed declaration/evidence comparison and output contracts."""

from datetime import UTC, datetime

import pytest

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector, canary_tool_eligible
from mcp_audit.models import (
    AuditReport,
    Confidence,
    PermissionCategory,
    ServerAudit,
    ToolAnnotations,
)
from mcp_audit.policy import PolicyConfig, ServerPolicyConfig, evaluate_policy
from mcp_audit.sarif import SarifGenerator
from mcp_audit.scorer import RiskScorer
from tests.conftest import make_server_config, make_tool
from tests.fixtures.evasion_server import tools_for


@pytest.mark.parametrize(
    ("name", "annotations", "expected"),
    [
        ("clock", ToolAnnotations(read_only_hint=True, open_world_hint=False), []),
        ("read_file", ToolAnnotations(read_only_hint=True, open_world_hint=False), []),
        ("write_file", ToolAnnotations(read_only_hint=False, destructive_hint=False), []),
        ("delete_file", ToolAnnotations(destructive_hint=True), []),
        ("fetch_url", ToolAnnotations(open_world_hint=True), []),
        ("delete_file", None, []),
        ("fetch_url", ToolAnnotations(), []),
        ("write_file", ToolAnnotations(read_only_hint=True), [("readOnlyHint", "file_write", "medium")]),
        (
            "delete_file",
            ToolAnnotations(read_only_hint=True),
            [("readOnlyHint", "file_write", "medium"), ("readOnlyHint", "destructive", "high")],
        ),
        (
            "delete_file",
            ToolAnnotations(destructive_hint=False),
            [("destructiveHint", "destructive", "high")],
        ),
        ("fetch_url", ToolAnnotations(open_world_hint=False), [("openWorldHint", "network", "medium")]),
        ("upload", ToolAnnotations(open_world_hint=False), [("openWorldHint", "exfiltration", "medium")]),
    ],
)
def test_annotation_golden_table(
    name: str, annotations: ToolAnnotations | None, expected: list[tuple[str, str, str]]
) -> None:
    findings = PermissionAnalyzer().analyze_annotation_contradictions(
        make_tool(name, annotations=annotations)
    )
    assert [(f.hint, f.category.value, f.severity) for f in findings] == expected


@pytest.mark.parametrize(
    ("keyword", "confidence", "contradicts"),
    [("remote", Confidence.LOW, False), ("fetch", Confidence.MEDIUM, True)],
)
def test_contradiction_requires_medium_keyword_confidence(
    keyword: str, confidence: Confidence, contradicts: bool
) -> None:
    tool = make_tool(
        "clock",
        input_schema={"properties": {keyword: {"type": "string"}}},
        annotations=ToolAnnotations(open_world_hint=False),
    )
    analyzer = PermissionAnalyzer()
    keyword_finding = next(f for f in analyzer.analyze_tool_keywords(tool) if f.category == "network")
    assert keyword_finding.confidence == confidence
    assert bool(analyzer.analyze_annotation_contradictions(tool)) is contradicts
    assert PermissionCategory.NETWORK in {f.category for f in analyzer.analyze_tool(tool)}


def _corpus_audit() -> ServerAudit:
    from mcp.types import Tool

    tool = ServerConnector._convert_tool(
        Tool.model_validate(tools_for("lying_annotations", "current", 0, "mcp-audit", 0.0)[0])
    )
    analyzer = PermissionAnalyzer()
    permissions = analyzer.analyze_server([tool])
    return ServerAudit(
        server=make_server_config(),
        connection_status="connected",
        tools=[tool],
        permissions=permissions,
        annotation_findings=analyzer.analyze_annotation_contradictions(tool),
        risk_score=RiskScorer().score_server(permissions),
    )


def _report(audit: ServerAudit) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="synthetic",
        os_platform="synthetic",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.0,
    )


def test_corpus_capability_evidence_is_restored_without_annotation_discount() -> None:
    audit = _corpus_audit()
    tool = audit.tools[0]
    analyzer = PermissionAnalyzer()
    keyword_only = analyzer.analyze_tool_keywords(tool.model_copy(update={"annotations": None}))
    restored = {f.category: f for f in audit.permissions}
    assert {f.category for f in keyword_only} <= restored.keys()
    for finding in keyword_only:
        if restored[finding.category].confidence != Confidence.DECLARED:
            assert restored[finding.category] == finding
    assert audit.risk_score is not None
    assert audit.risk_score.composite >= RiskScorer().score_server(keyword_only).composite
    assert {f.severity for f in audit.annotation_findings} == {"medium", "high"}


def test_annotation_json_and_sarif_contract() -> None:
    report = _report(_corpus_audit())
    payload = report.model_dump(mode="json")
    assert payload["schema_version"] == 1
    findings = payload["audits"][0]["annotation_findings"]
    assert {f["rule_id"] for f in findings} == {"MCP043"}
    assert {f["kind"] for f in findings} == {"annotation_contradiction"}
    assert all(f["confidence"] in {"medium", "high"} and f["field_paths"] for f in findings)
    assert (
        AuditReport.model_validate(payload).audits[0].annotation_findings
        == report.audits[0].annotation_findings
    )
    del payload["audits"][0]["annotation_findings"]
    assert AuditReport.model_validate(payload).audits[0].annotation_findings == []
    sarif = SarifGenerator().generate(report)
    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "MCP043"]
    assert {r["level"] for r in results} == {"warning", "error"}
    assert len({r["partialFingerprints"]["mcpAuditStableId"] for r in results}) == len(findings)


@pytest.mark.parametrize("threshold", ["medium", "high"])
def test_annotation_policy_uses_permission_severity_threshold(threshold: str) -> None:
    audit = _corpus_audit()
    audit.permissions = []  # Isolate the contradiction rule from capability gates.
    report = _report(audit)
    policies = [
        PolicyConfig(fail_on_severity=threshold),
        PolicyConfig(fail_on_permission_severity=threshold),
        PolicyConfig(
            server_rules={audit.server.name: ServerPolicyConfig(fail_on_permission_severity=threshold)}
        ),
    ]
    for policy in policies:
        result = evaluate_policy(report, policy)
        assert not result.passed
        assert len(result.violations) == (2 if threshold == "medium" else 1)
        assert all("MCP043" in v.message for v in result.violations)


def test_canary_still_vetoes_served_destructive_annotation() -> None:
    tool = make_tool(
        "clock",
        input_schema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(read_only_hint=True, destructive_hint=True, open_world_hint=False),
    )
    assert PermissionAnalyzer().analyze_annotation_contradictions(tool) == []
    assert not canary_tool_eligible(tool, explicitly_safe=True)
