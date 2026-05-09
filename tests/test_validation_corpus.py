"""Regression test for the real-world MCP server validation corpus."""

from __future__ import annotations

from tests.validation.validate_patterns import run_validation


def test_real_world_validation_corpus_passes() -> None:
    assert run_validation() == 0
