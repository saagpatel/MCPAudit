"""Tests for checked-in example files."""

from __future__ import annotations

from pathlib import Path

import yaml

CI_EXAMPLES = sorted(Path("examples/ci").glob("*.yml"))


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
