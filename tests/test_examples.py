"""Tests for checked-in example files."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from mcp_audit.models import AuditReport

CI_EXAMPLES = sorted(Path("examples/ci").glob("*.yml"))
CONSUMER_EXAMPLES = sorted(Path("examples/consumers").glob("parse*"))
POLICY_EXAMPLES = sorted(Path("examples/policies").glob("*.yaml"))
PROMPT_RESOURCE_REPORT = Path("tests/fixtures/reports/prompt_resource_report.json")
SCHEMA_PATH = Path("examples/schemas/audit-report.schema.json")


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


def test_consumer_examples_are_documented() -> None:
    readme = Path("examples/consumers/README.md").read_text()
    assert CONSUMER_EXAMPLES
    for example_path in CONSUMER_EXAMPLES:
        assert example_path.name in readme
