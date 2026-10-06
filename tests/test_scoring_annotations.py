"""P2-1 synthetic score, missing-hint, and SARIF compatibility acceptance."""

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, ServerAudit, ServerConfig, ToolAnnotations, ToolInfo
from mcp_audit.overrides import OverrideApplier, OverrideConfig, PermissionOverride, ServerToolOverride
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator, _stable_fingerprint
from tests.conftest import make_server_config, make_tool

FIXTURE = Path(__file__).parent / "fixtures/scoring_annotations.json"


async def _scan(
    name: str, monkeypatch: pytest.MonkeyPatch, overrides: list[ServerToolOverride] | None = None
) -> AuditReport:
    tools = [ToolInfo.model_validate(tool) for tool in json.loads(FIXTURE.read_text())[name]]

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="connected", tools=tools)

    monkeypatch.setattr(ServerConnector, "connect", connect)
    return await run_scan(
        ScanOptions(config_only=True, inject_check=True, trifecta_check=True),
        servers=[make_server_config(name=name)],
        override_applier=OverrideApplier(OverrideConfig(overrides=overrides or [])),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "composite", "alert_score", "missing", "permissions"),
    [
        ("clock", 0.0, 2.5, True, []),
        ("fully_annotated_clock", 0.0, 1.0, False, []),
        ("unlabeled", 0.0, 3.5, True, []),
        ("read_file", 0.9, 1.0, False, ["file_read"]),
    ],
)
async def test_scoring_golden_table(
    name: str,
    composite: float,
    alert_score: float,
    missing: bool,
    permissions: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _scan(name, monkeypatch)
    audit = report.audits[0]
    assert audit.risk_score is not None
    assert audit.risk_score.composite == pytest.approx(composite)
    assert audit.permission_alert_score == pytest.approx(alert_score)
    assert audit.annotations_missing is missing
    assert [f.category.value for f in audit.permissions] == permissions
    payload = report.model_dump(mode="json")
    assert payload["schema_version"] == 1
    assert payload["audits"][0]["annotations_missing"] is missing
    assert AuditReport.model_validate(payload).audits[0].annotations_missing is missing
    del payload["audits"][0]["annotations_missing"]
    assert not AuditReport.model_validate(payload).audits[0].annotations_missing

    results = SarifGenerator().generate(report)["runs"][0]["results"]
    notices = [r for r in results if r["properties"].get("kind") == "annotations_missing"]
    assert len(notices) == int(missing)
    if missing:
        assert notices[0]["ruleId"] == "MCP005"
        assert notices[0]["level"] == "note"
        assert notices[0]["partialFingerprints"]["mcpAuditStableId"] == _stable_fingerprint(
            "MCP005/annotations_missing", name, ""
        )
        assert notices[0]["partialFingerprints"]["mcpAuditStableId"] != _stable_fingerprint(
            "MCP005", name, "annotations_missing"
        )  # A genuine tool with that name must retain a distinct fingerprint.
        assert evaluate_policy(report, PolicyConfig(fail_on_severity="low", max_risk=0.1)).passed
    if composite == 0.0:
        assert all(r["level"] == "note" for r in results)
    else:
        result = next(r for r in results if r["ruleId"] == "MCP001")
        assert result["partialFingerprints"]["mcpAuditStableId"] == _stable_fingerprint(
            "MCP001", name, "read_file"
        )

    output = io.StringIO()
    ReportGenerator(Console(file=output, width=160)).render_terminal(report, verbose=True)
    assert output.getvalue().count("annotations_missing") == int(missing)
    if name.startswith("clock") or name == "fully_annotated_clock":
        assert "read-only (says so itself)" in output.getvalue()


@pytest.mark.anyio
async def test_risky_fixture_keeps_injection_and_chain_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    report = await _scan("risky", monkeypatch)
    audit = report.audits[0]
    assert audit.annotations_missing
    assert any(f.tool_name == "read_file" and f.rule_id == "MCP007" for f in audit.injection_findings)
    assert audit.trifecta_findings
    results = SarifGenerator().generate(report)["runs"][0]["results"]
    assert any(r["ruleId"] == "MCP007" and r["level"] == "error" for r in results)
    assert sum(r["properties"].get("kind") == "annotations_missing" for r in results) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("server", "tool", "alert_score", "level"),
    [
        (None, None, 7.1, "error"),
        ("*", "*", 3.6, "warning"),
        ("capability_levels", "*", 3.6, "warning"),
        ("capability_levels", "read_file", 7.1, "error"),
    ],
)
async def test_capability_sarif_levels_and_fingerprints_remain_compatible(
    server: str | None,
    tool: str | None,
    alert_score: float,
    level: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overrides = (
        [
            ServerToolOverride(
                server=server,
                tool=tool,
                permissions=PermissionOverride(network=False, destructive=False),
            )
        ]
        if server is not None and tool is not None
        else []
    )
    report = await _scan("capability_levels", monkeypatch, overrides)
    score = report.audits[0].risk_score
    assert score is not None and score.composite == pytest.approx(3.6)
    assert report.audits[0].permission_alert_score == pytest.approx(alert_score)
    assert {finding.category.value for finding in report.audits[0].permissions} == {
        "file_read",
        "shell_execution",
    }
    payload = report.model_dump(mode="json")
    assert payload["schema_version"] == 1
    for candidate in [report, AuditReport.model_validate(payload), report.redacted()]:
        results = SarifGenerator().generate(candidate)["runs"][0]["results"]
        for rule_id, tool_name in [("MCP001", "read_file"), ("MCP004", "shell")]:
            result = next(r for r in results if r["ruleId"] == rule_id)
            assert result["level"] == level
            assert result["partialFingerprints"]["mcpAuditStableId"] == _stable_fingerprint(
                rule_id, "capability_levels", tool_name
            )
        notice = next(r for r in results if r["properties"].get("kind") == "annotations_missing")
        assert notice["level"] == "note"

    del payload["audits"][0]["permission_alert_score"]
    legacy_report = AuditReport.model_validate(payload)
    assert legacy_report.audits[0].permission_alert_score is None
    legacy_results = SarifGenerator().generate(legacy_report)["runs"][0]["results"]
    assert all(r["level"] == "error" for r in legacy_results if r["ruleId"] in {"MCP001", "MCP004"})


@pytest.mark.parametrize(
    ("annotations", "missing"),
    [
        (None, True),
        (ToolAnnotations(), True),
        (ToolAnnotations(read_only_hint=True, open_world_hint=False), False),
        (ToolAnnotations(destructive_hint=False, open_world_hint=False), False),
        (ToolAnnotations(destructive_hint=True, open_world_hint=False), False),
        (ToolAnnotations(open_world_hint=False), True),
        (ToolAnnotations(read_only_hint=True), True),
    ],
)
def test_only_applicable_null_hints_produce_information(
    annotations: ToolAnnotations | None, missing: bool
) -> None:
    analyzer = PermissionAnalyzer()
    assert analyzer.annotations_missing([make_tool("clock", annotations=annotations)]) is missing
    assert not analyzer.annotations_missing([])


@pytest.mark.parametrize(
    ("name", "context", "category"),
    [
        ("set_mode", "file path", "file_write"),
        ("add_label", "file path", "file_write"),
        ("commit", "repository", "file_write"),
        ("export", "recipient", "exfiltration"),
        ("reply", "email recipient", "exfiltration"),
        ("forward", "endpoint", "exfiltration"),
        ("list_items", "directory", "file_read"),
        ("open_item", "file path", "file_read"),
        ("describe_item", "file path", "file_read"),
    ],
)
def test_ambiguous_keywords_require_context(name: str, context: str, category: str) -> None:
    analyzer = PermissionAnalyzer()
    assert not analyzer.analyze_tool_keywords(make_tool(name))
    tool = make_tool(name, input_schema={"properties": {"detail": {"description": context}}})
    finding = next(f for f in analyzer.analyze_tool_keywords(tool) if f.category.value == category)
    assert name.split("_")[0] in finding.evidence
    assert "/name" in finding.field_paths
