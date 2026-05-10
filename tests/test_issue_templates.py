"""Tests for GitHub issue templates that feed project regression coverage."""

from pathlib import Path

FEEDBACK_TEMPLATE = Path(".github/ISSUE_TEMPLATE/feedback.md")
FEEDBACK_DOC = Path("docs/FEEDBACK-TO-FIXTURES.md")


def test_feedback_template_collects_fixture_ready_context() -> None:
    text = FEEDBACK_TEMPLATE.read_text()

    assert "## Reproduction mode" in text
    assert "`scan --skip-connect`" in text
    assert "`scan --inject-check`" in text
    assert "`scan --pin-check`" in text
    assert "`scan --policy`" in text
    assert "JSON or SARIF consumer parsing" in text
    assert "## Expected regression assertion" in text
    assert "## Minimal redacted fixture" in text
    assert "## Fixture permission" in text


def test_feedback_template_preserves_redaction_and_private_disclosure_guidance() -> None:
    text = FEEDBACK_TEMPLATE.read_text()

    assert "Do not include" in text
    assert "API keys, tokens, passwords" in text
    assert "private file paths" in text
    assert "internal hostnames" in text
    assert "private disclosure" in text
    assert "SECURITY.md" in text


def test_feedback_docs_explain_public_fixture_intake() -> None:
    doc = FEEDBACK_DOC.read_text()
    readme = Path("README.md").read_text()

    assert "The public feedback issue template mirrors this intake path." in doc
    assert "the expected regression assertion" in doc
    assert "Security-sensitive false negatives" in doc
    assert "docs/FEEDBACK-TO-FIXTURES.md" in readme
