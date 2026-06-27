"""Public-safe checks for the MCP prompt-injection sandbox fixtures."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_audit.api import scan_config_only
from mcp_audit.injection import InjectionDetector
from mcp_audit.models import AuditReport, ToolAnnotations, ToolInfo

SANDBOX_DIR = Path("examples/sandbox")
SCENARIOS_PATH = SANDBOX_DIR / "scenarios.json"
CONFIG_PATH = SANDBOX_DIR / "fixtures" / "synthetic-mcp-config.json"
REPORT_PATH = SANDBOX_DIR / "fixtures" / "config-only-report.json"
MANIFEST_PATH = SANDBOX_DIR / "fixtures" / "connected-tool-manifest.json"

PRIVATE_OR_SECRET_PATTERNS = [
    re.compile(r"/Users/[A-Za-z0-9._-]+"),
    re.compile(r"/home/[A-Za-z0-9._-]+"),
    re.compile(r"[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"\bghp_[A-Za-z0-9_]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
]


def _load_scenarios() -> dict[str, Any]:
    return json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))


def _load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _iter_sandbox_files() -> list[Path]:
    return sorted(
        path for path in SANDBOX_DIR.rglob("*") if path.is_file() and path.suffix in {".html", ".json", ".md"}
    )


def _tool_from_fixture(raw: dict[str, Any]) -> ToolInfo:
    annotations = None
    if raw.get("annotations"):
        annotations = ToolAnnotations(**raw["annotations"])
    return ToolInfo(
        name=raw["name"],
        description=raw.get("description"),
        input_schema=raw.get("input_schema"),
        annotations=annotations,
    )


def _report_signature(report: AuditReport) -> dict[str, Any]:
    return {
        "servers_discovered": report.servers_discovered,
        "servers_connected": report.servers_connected,
        "servers_failed": report.servers_failed,
        "total_tools": report.total_tools,
        "statuses": [audit.connection_status for audit in report.audits],
        "server_names": [audit.server.name for audit in report.audits],
        "permission_categories_by_server": {
            audit.server.name: sorted({permission.category.value for permission in audit.permissions})
            for audit in report.audits
        },
        "config_health": sorted(
            (finding.server_name, finding.finding_type, finding.severity.value)
            for finding in report.config_health_findings
        ),
    }


def test_sandbox_files_are_public_safe() -> None:
    assert _iter_sandbox_files()
    for path in _iter_sandbox_files():
        text = path.read_text(encoding="utf-8")
        for pattern in PRIVATE_OR_SECRET_PATTERNS:
            assert not pattern.search(text), f"{path} matched public-safety pattern {pattern.pattern!r}"


def test_sandbox_schema_has_benign_twins_and_source_backing() -> None:
    data = _load_scenarios()
    index = (SANDBOX_DIR / "index.html").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert data["schema_version"] == "mcpaudit.prompt_injection_sandbox.v1"
    assert len(data["source_backing"]) >= 3
    assert all(source["url"].startswith("https://") for source in data["source_backing"])
    assert "fixtures/config-only-report.json" in index
    assert "fixtures/connected-tool-manifest.json" in index
    assert "examples/sandbox/" in readme

    for scenario in data["scenarios"]:
        kinds = {twin["kind"] for twin in scenario["twins"]}
        assert "benign" in kinds
        assert any(kind in kinds for kind in {"risky-lookalike", "malicious-lookalike"})
        assert scenario["config_only_boundary"]
        assert scenario["connected_boundary"]
        assert scenario["why_this_matters"]
        assert scenario["calibration_note"]


def test_connected_manifest_matches_scenario_tool_metadata() -> None:
    data = _load_scenarios()
    manifest = _load_manifest()

    assert manifest["schema_version"] == "mcpaudit.sandbox.connected_manifest.v1"
    assert manifest["proof_boundary"]

    expected_keys: set[str] = set()
    for scenario in data["scenarios"]:
        for twin in scenario["twins"]:
            key = f"{scenario['id']}/{twin['kind']}"
            expected_keys.add(key)
            tool_set = manifest["tool_sets"][key]
            assert tool_set["server"] == twin["server"]
            assert tool_set["tools"] == twin["tool_metadata"]
            assert tool_set["prompts"] == []
            assert tool_set["resources"] == []

    assert set(manifest["tool_sets"]) == expected_keys


async def test_sandbox_config_runs_through_config_only_scan() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = await scan_config_only(config, source="<sandbox-fixture>")

    finding_types = {finding.finding_type for finding in report.config_health_findings}
    permission_categories = {
        permission.category.value for audit in report.audits for permission in audit.permissions
    }
    server_names = {audit.server.name for audit in report.audits}

    assert server_names == {
        "toy-notes-reader",
        "toy-filesystem-wide",
        "toy-weather",
        "toy-weather-lookalike",
        "toy-shell-exporter",
    }
    assert {"file_read", "file_write", "network", "shell_execution"} <= permission_categories
    assert {
        "credential_heavy_config",
        "package_runner_source_review",
        "remote_endpoint",
        "remote_url_argument",
        "shell_wrapper_launch",
    } <= finding_types
    assert all(audit.connection_status == "skipped" for audit in report.audits)
    assert all(audit.tools == [] for audit in report.audits)


async def test_static_report_fixture_matches_current_config_only_scan() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    fresh_report = await scan_config_only(config, source=str(CONFIG_PATH))
    fixture_report = AuditReport.model_validate_json(REPORT_PATH.read_text(encoding="utf-8"))

    assert fixture_report.hostname == "sandbox-host"
    assert fixture_report.scan_duration_seconds == 0.0
    assert _report_signature(fixture_report) == _report_signature(fresh_report)
    assert all(audit.connection_status == "skipped" for audit in fixture_report.audits)
    assert all(audit.tools == [] for audit in fixture_report.audits)
    assert all(audit.injection_findings == [] for audit in fixture_report.audits)


def test_sandbox_tool_metadata_matches_injection_detector() -> None:
    data = _load_scenarios()
    manifest = _load_manifest()
    injection_scenario = next(
        scenario for scenario in data["scenarios"] if scenario["id"] == "tool-description-injection"
    )
    detector = InjectionDetector()

    by_kind = {twin["kind"]: twin for twin in injection_scenario["twins"]}
    benign_tools = [
        _tool_from_fixture(tool)
        for tool in manifest["tool_sets"][f"{injection_scenario['id']}/{by_kind['benign']['kind']}"]["tools"]
    ]
    risky_tools = [
        _tool_from_fixture(tool)
        for tool in manifest["tool_sets"][
            f"{injection_scenario['id']}/{by_kind['malicious-lookalike']['kind']}"
        ]["tools"]
    ]

    assert detector.scan_server(benign_tools) == []
    pattern_names = {finding.pattern_name for finding in detector.scan_server(risky_tools)}
    assert {"ignore_instructions", "prompt_leak"} <= pattern_names


def test_sandbox_expected_findings_are_review_findings_not_claims_of_exploit() -> None:
    data = _load_scenarios()
    rendered = json.dumps(data).lower()

    forbidden_claims = [
        "proves malicious",
        "will exfiltrate",
        "definitely malicious",
        "guaranteed exploit",
    ]
    for claim in forbidden_claims:
        assert claim not in rendered

    findings = [
        finding
        for scenario in data["scenarios"]
        for twin in scenario["twins"]
        for finding in twin.get("expected_findings", [])
    ]
    assert findings
    for finding in findings:
        assert finding["severity"] in {"low", "medium", "high"}
        assert finding["evidence"]
        assert finding["what_mcpaudit_can_prove"]
        assert finding["review_action"]
