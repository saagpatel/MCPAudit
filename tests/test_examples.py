"""Tests for checked-in example files."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_audit.models import AuditReport

CI_EXAMPLES = sorted(Path("examples/ci").glob("*.yml"))
DOCS_REFERENCING_ADOPTION_EXAMPLES = [
    Path("README.md"),
    Path("docs/ADOPTION-GUIDE.md"),
    Path("docs/GOLDEN-ROLLOUT.md"),
    Path("docs/PIN-MAINTENANCE.md"),
]
CONSUMER_EXAMPLES = sorted(
    path
    for path in Path("examples/consumers").iterdir()
    if path.name in {"dashboard_summary.py", "parse-report.mjs", "parse_report.py"}
)
MAINTENANCE_EXAMPLES = sorted(Path("examples/maintenance").glob("*.sh"))
POLICY_EXAMPLES = sorted(Path("examples/policies").glob("*.yaml"))
PROMPT_RESOURCE_REPORT = Path("tests/fixtures/reports/prompt_resource_report.json")
CONFIG_ONLY_REPORT = Path("tests/fixtures/reports/config_only_report.json")
DASHBOARD_STATUS_REPORT = Path("tests/fixtures/reports/dashboard_status_report.json")
FIELD_REPORTS = sorted(Path("tests/fixtures/reports/field").glob("*.json"))
LEGACY_REPORTS = sorted(Path("tests/fixtures/reports/legacy").glob("*.json"))
CONSUMER_CONTRACT_REPORTS = [
    CONFIG_ONLY_REPORT,
    DASHBOARD_STATUS_REPORT,
    PROMPT_RESOURCE_REPORT,
    *FIELD_REPORTS,
    *LEGACY_REPORTS,
]
SCHEMA_PATH = Path("examples/schemas/audit-report.schema.json")
MCP_TRUST_PACKET = Path("docs/MCP-TRUST-PACKET.md")
LAUNCH_POSTS = Path("launch-posts.md")
CONFIG_ONLY_SCAN_ASSET = Path("docs/assets/mcp-audit-config-only-scan.png")
HERO_SCAN_GIF = Path("docs/assets/hero-scan.gif")
HERO_DEMO_CONFIG = Path("docs/assets/hero-demo-config.json")
HERO_TAPE = Path("docs/assets/hero.tape")


def test_ci_examples_are_valid_yaml() -> None:
    assert CI_EXAMPLES
    for example_path in CI_EXAMPLES:
        parsed = yaml.safe_load(example_path.read_text())
        assert isinstance(parsed, dict)
        assert parsed.get("jobs")


def test_ci_examples_install_published_package() -> None:
    for example_path in CI_EXAMPLES:
        text = example_path.read_text()
        assert "mcp-permission-audit" in text
        assert "mcp-audit scan" in text


def test_ci_examples_default_to_config_only_adoption() -> None:
    for example_path in CI_EXAMPLES:
        text = example_path.read_text()
        assert "--skip-connect" in text


def test_ci_examples_keep_reports_when_gates_fail() -> None:
    for example_path in CI_EXAMPLES:
        parsed = yaml.safe_load(example_path.read_text())
        steps = parsed["jobs"][next(iter(parsed["jobs"]))]["steps"]
        step_text = json.dumps(steps)
        assert "upload-artifact" in step_text or "upload-sarif" in step_text

        if "--policy" in step_text:
            assert "always()" in step_text


def test_adoption_docs_reference_current_examples() -> None:
    combined_docs = "\n".join(path.read_text() for path in DOCS_REFERENCING_ADOPTION_EXAMPLES)
    required_paths = [
        "examples/ci/config-health-policy.yml",
        "examples/ci/generic-json-policy.yml",
        "examples/ci/github-code-scanning.yml",
        "examples/ci/pin-stale-review.yml",
        "examples/consumers/",
        "examples/policies/",
    ]

    for required_path in required_paths:
        assert required_path in combined_docs


def test_mcp_trust_packet_is_discoverable_and_safe() -> None:
    readme = Path("README.md").read_text()
    packet = MCP_TRUST_PACKET.read_text()

    assert "docs/MCP-TRUST-PACKET.md" in readme
    assert "uvx --from fastmcp-builder==0.3.0 mcpforge init" in packet
    assert "uvx --from mcp-permission-audit==1.13.1 mcp-audit scan" in packet
    assert "It has been smoke-checked" in packet
    assert "--config-only" in packet
    assert "--skip-connect" in packet
    assert "--redact" in packet
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in packet
    assert "`remote_endpoint` config-health finding" in packet
    assert "Do not include:" in packet
    assert "bridge-db` only as local operating-state infrastructure" in packet


def test_external_launch_checklist_links_credible_public_path() -> None:
    readme = Path("README.md").read_text()
    demo_assets = Path("DEMO-ASSETS.md").read_text()

    assert CONFIG_ONLY_SCAN_ASSET.exists()
    assert CONFIG_ONLY_SCAN_ASSET.stat().st_size > 0
    assert HERO_DEMO_CONFIG.exists()
    hero_config = json.loads(HERO_DEMO_CONFIG.read_text())
    assert sorted(hero_config["mcpServers"]) == ["fetch", "sequential-thinking", "time"]
    assert HERO_SCAN_GIF.exists()
    assert HERO_SCAN_GIF.stat().st_size > 0
    assert "docs/assets/hero-scan.gif" in readme
    assert "docs/assets/hero-demo-config.json" in demo_assets
    assert HERO_TAPE.exists()
    hero_tape = HERO_TAPE.read_text()
    assert "Output docs/assets/hero-scan.gif" in hero_tape
    assert "docs/assets/hero-demo-config.json --config-only --ssrf-check" in hero_tape
    assert "docs/assets/hero.tape" in demo_assets
    assert "auth tokens, real local paths, or placeholder remote URLs" in demo_assets
    assert "## External launch checklist" in readme
    assert "docs/assets/mcp-audit-config-only-scan.png" in readme
    assert "docs/MCP-TRUST-PACKET.md" in readme
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in readme
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in readme
    assert "launch-posts.md" in readme
    assert "pre-beta until two external redacted reports land" in readme
    launch_posts = LAUNCH_POSTS.read_text()
    assert "## 1. Show HN / r/mcp" in launch_posts
    assert "## 2. LinkedIn" in launch_posts
    assert "Title A/B + posting-time plan" in launch_posts
    assert "docs/assets/hero-scan.gif" in launch_posts
    assert "docs/assets/mcp-audit-config-only-scan.png" in launch_posts
    assert "record via `DEMO-ASSETS.md` first if possible" not in launch_posts
    assert "not a real workstation" in launch_posts


def test_hero_recording_recipe_is_public_and_scoped() -> None:
    config = json.loads(HERO_DEMO_CONFIG.read_text())
    tape = HERO_TAPE.read_text()
    demo_assets = Path("DEMO-ASSETS.md").read_text()

    servers = config["mcpServers"]
    assert set(servers) == {"fetch", "sequential-thinking", "time"}
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in HERO_DEMO_CONFIG.read_text()
    assert "/tmp/workspace" not in HERO_DEMO_CONFIG.read_text()
    assert "--config docs/assets/hero-demo-config.json --config-only --ssrf-check" in tape
    assert "export COLUMNS=185" in tape
    assert "never reads your real MCP configs" in tape
    assert "docs/assets/hero-scan.gif" in tape
    assert "docs/assets/hero-demo-config.json" in demo_assets
    assert "docs/assets/hero.tape" in demo_assets
    assert "fetch`, `sequential-thinking`, `time" in demo_assets


def test_stale_pin_review_examples_are_read_only() -> None:
    ci_text = Path("examples/ci/pin-stale-review.yml").read_text()
    script_text = Path("examples/maintenance/stale-pin-review.sh").read_text()
    assert "mcp-audit pin --stale --json" in ci_text
    assert "mcp-audit pin --stale --json" in script_text
    assert "mcp-audit pin --clear-stale --json" in ci_text
    assert "mcp-audit pin --clear-stale --apply" not in ci_text
    assert "mcp-audit pin --clear-stale --json" in script_text
    assert "mcp-audit pin --clear <server>" in script_text


def test_maintenance_shell_examples_parse() -> None:
    assert MAINTENANCE_EXAMPLES
    for example_path in MAINTENANCE_EXAMPLES:
        subprocess.run(["bash", "-n", str(example_path)], check=True)


def test_policy_pack_readme_mentions_each_policy() -> None:
    readme = Path("examples/policies/README.md").read_text()
    assert POLICY_EXAMPLES
    for policy_path in POLICY_EXAMPLES:
        assert policy_path.name in readme


def test_generated_json_schema_matches_current_report_model() -> None:
    expected = json.loads(SCHEMA_PATH.read_text())
    assert expected == AuditReport.model_json_schema()


def test_python_consumer_example_parses_prompt_resource_report() -> None:
    result = subprocess.run(
        [sys.executable, "examples/consumers/parse_report.py", str(PROMPT_RESOURCE_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(result.stdout)
    assert rows[0]["server"] == "knowledge"
    assert rows[0]["tool_risk"] == 0.0
    assert rows[0]["non_tool_risk"] > 0.0
    assert rows[0]["capability_findings"] == 2
    assert rows[0]["injection_findings"] == 1
    assert {"target_type": "prompt", "target_name": "review_code", "kind": "injection"} in rows[0][
        "non_tool_targets"
    ]


def test_python_consumer_example_parses_config_health() -> None:
    result = subprocess.run(
        [sys.executable, "examples/consumers/parse_report.py", str(CONFIG_ONLY_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(result.stdout)
    assert rows[0]["server"] == "remote-api"
    assert rows[0]["config_health_findings"] == 1
    assert rows[0]["config_health_by_severity"] == {"medium": 1}
    assert rows[0]["config_health_types"] == ["remote_endpoint"]


def test_dashboard_consumer_example_parses_config_health() -> None:
    result = subprocess.run(
        [sys.executable, "examples/consumers/dashboard_summary.py", str(CONFIG_ONLY_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(result.stdout)
    assert summary["servers_discovered"] == 1
    assert summary["status_counts"] == {"skipped": 1}
    assert summary["policy_failure_count"] == 0
    assert summary["max_tool_risk"] == 4.0
    assert summary["config_health"] == {"medium": 1}
    assert summary["attention"][0]["server"] == "remote-api"
    assert summary["attention"][0]["reasons"] == ["config_health"]
    assert summary["servers"][0]["server"] == "remote-api"
    assert summary["servers"][0]["config_health"] == {"medium": 1}


def test_dashboard_consumer_example_parses_status_report() -> None:
    AuditReport.model_validate_json(DASHBOARD_STATUS_REPORT.read_text())
    result = subprocess.run(
        [sys.executable, "examples/consumers/dashboard_summary.py", str(DASHBOARD_STATUS_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(result.stdout)
    servers = {server["server"]: server for server in summary["servers"]}

    assert summary["servers_discovered"] == 3
    assert summary["servers_failed"] == 1
    assert summary["status_counts"] == {"skipped": 1, "connected": 1, "failed": 1}
    assert summary["policy_passed"] is False
    assert summary["policy_failure_count"] == 2
    assert summary["max_tool_risk"] == 8.0
    assert summary["max_non_tool_risk"] == 5.95
    assert summary["config_health"] == {"medium": 1}
    assert {row["server"] for row in summary["attention"]} == {"remote-api", "knowledge", "shell"}
    assert servers["remote-api"]["config_health"] == {"medium": 1}
    assert servers["knowledge"]["non_tool_risk"] == 5.95
    assert servers["knowledge"]["policy_failures"] == 1
    assert servers["shell"]["status"] == "failed"
    assert servers["shell"]["tool_risk"] == 8.0
    assert servers["shell"]["policy_failures"] == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_node_consumer_example_parses_prompt_resource_report() -> None:
    result = subprocess.run(
        ["node", "examples/consumers/parse-report.mjs", str(PROMPT_RESOURCE_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(result.stdout)
    assert rows[0]["server"] == "knowledge"
    assert rows[0]["non_tool_risk"] > 0.0
    assert any(target["target_type"] == "resource" for target in rows[0]["non_tool_targets"])


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_node_consumer_example_parses_config_health() -> None:
    result = subprocess.run(
        ["node", "examples/consumers/parse-report.mjs", str(CONFIG_ONLY_REPORT)],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(result.stdout)
    assert rows[0]["server"] == "remote-api"
    assert rows[0]["config_health_findings"] == 1
    assert rows[0]["config_health_by_severity"] == {"medium": 1}
    assert rows[0]["config_health_types"] == ["remote_endpoint"]


def test_consumer_contract_reports_parse_with_python_and_dashboard_examples() -> None:
    assert FIELD_REPORTS
    for report_path in CONSUMER_CONTRACT_REPORTS:
        report = AuditReport.model_validate_json(report_path.read_text())
        rows = _run_python_consumer(report_path)
        dashboard = _run_dashboard_consumer(report_path)

        assert len(rows) == len(report.audits)
        assert dashboard["servers_discovered"] == report.servers_discovered
        assert sum(dashboard["status_counts"].values()) == len(report.audits)
        assert all("tool_risk" in row for row in rows)
        assert all("non_tool_risk" in row for row in rows)
        assert all("config_health_findings" in row for row in rows)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_node_consumer_contract_matches_python_consumer() -> None:
    assert FIELD_REPORTS
    for report_path in CONSUMER_CONTRACT_REPORTS:
        assert _run_node_consumer(report_path) == _run_python_consumer(report_path)


def test_consumer_examples_are_documented() -> None:
    readme = Path("examples/consumers/README.md").read_text()
    assert CONSUMER_EXAMPLES
    for example_path in CONSUMER_EXAMPLES:
        assert example_path.name in readme


def test_golden_rollout_doc_is_linked_and_staged() -> None:
    rollout = Path("docs/GOLDEN-ROLLOUT.md").read_text()
    readme = Path("README.md").read_text()
    adoption = Path("docs/ADOPTION-GUIDE.md").read_text()

    assert "mcp-audit scan --skip-connect" in rollout
    assert "mcp-audit scan --inject-check" in rollout
    assert "mcp-audit pin" in rollout
    assert "--policy examples/policies/balanced-team-ci.yaml" in rollout
    assert "docs/GOLDEN-ROLLOUT.md" in readme
    assert "docs/GOLDEN-ROLLOUT.md" in adoption


def test_evidence_intake_doc_tracks_next_milestone() -> None:
    readme = Path("README.md").read_text()
    roadmap = Path("docs/ROADMAP-NEXT.md").read_text()
    intake = Path("docs/1.5-EVIDENCE-INTAKE.md").read_text()
    decision = Path("docs/1.5-RELEASE-DECISION.md").read_text()
    beta_evidence = Path("docs/BETA-READINESS-EVIDENCE.md").read_text()
    field_reports = Path("docs/FIELD-REPORTS.md").read_text()

    assert "docs/1.5-EVIDENCE-INTAKE.md" in readme
    assert "docs/BETA-READINESS-EVIDENCE.md" in readme
    assert "docs/FIELD-REPORTS.md" in readme
    assert "docs/1.5-EVIDENCE-INTAKE.md" in roadmap
    assert "docs/1.5-RELEASE-DECISION.md" in roadmap
    assert "docs/BETA-READINESS-EVIDENCE.md" in roadmap
    assert "docs/FIELD-REPORTS.md" in roadmap
    assert "https://github.com/saagpatel/MCPAudit/milestone/1" in intake
    assert "https://github.com/saagpatel/MCPAudit/milestone/2" in beta_evidence
    assert "https://github.com/saagpatel/MCPAudit/milestone/3" in field_reports
    assert "ship `1.5.0` as adoption hardening, not beta" in decision
    assert "Ship `1.5.1` as polish instead of `1.6.0`" in beta_evidence
    assert "Ship `1.5.2` as polish instead of `1.6.0`" in field_reports
    for issue_number in ("66", "67", "68", "69"):
        assert f"https://github.com/saagpatel/MCPAudit/issues/{issue_number}" in intake
    for issue_number in ("77", "78", "79", "80"):
        assert f"https://github.com/saagpatel/MCPAudit/issues/{issue_number}" in field_reports


def _run_python_consumer(report_path: Path) -> list[dict[str, Any]]:
    result = subprocess.run(
        [sys.executable, "examples/consumers/parse_report.py", str(report_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    return parsed


def _run_node_consumer(report_path: Path) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["node", "examples/consumers/parse-report.mjs", str(report_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    return parsed


def _run_dashboard_consumer(report_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "examples/consumers/dashboard_summary.py", str(report_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    return parsed
