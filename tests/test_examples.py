"""Tests for checked-in example files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from mcp_audit.models import AuditReport

CI_EXAMPLES = sorted(Path("examples/ci").glob("*.yml"))
POLICY_EXAMPLES = sorted(Path("examples/policies").glob("*.yaml"))
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
