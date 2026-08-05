"""Tests for GitHub issue templates that feed project regression coverage."""

from pathlib import Path

FEEDBACK_TEMPLATE = Path(".github/ISSUE_TEMPLATE/feedback.md")
FIELD_REPORT_TEMPLATE = Path(".github/ISSUE_TEMPLATE/field_report.md")
FEEDBACK_DOC = Path("docs/FEEDBACK-TO-FIXTURES.md")
FIELD_REPORT_DOC = Path("docs/FIELD-REPORTS.md")
FIELD_REPORT_REQUEST_DOC = Path("docs/EXTERNAL-FIELD-REPORT-REQUEST.md")
FIELD_REPORT_OUTREACH_DOC = Path("docs/EXTERNAL-OUTREACH-MESSAGES.md")
SHOW_HN_DRAFT_DOC = Path("docs/SHOW-HN-DRAFT.md")
MCP_TRUST_PACKET_DOC = Path("docs/MCP-TRUST-PACKET.md")
SOLO_EVIDENCE_DOC = Path("docs/SOLO-EVIDENCE.md")
FIELD_REPORT_COMMAND = (
    "uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact"
)


def test_feedback_template_collects_fixture_ready_context() -> None:
    text = FEEDBACK_TEMPLATE.read_text()

    assert "## Reproduction mode" in text
    assert "`scan --skip-connect`" in text
    assert "`scan --inject-check`" in text
    assert "`scan --pin-check`" in text
    assert "`scan --policy`" in text
    assert "JSON or SARIF consumer parsing" in text
    assert "Dashboard or CI status-page integration" in text
    assert "## Expected regression assertion" in text
    assert "Prompt/resource `non_tool_risk` behavior should change" in text
    assert "External redacted field report" in text
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
    assert "Active Follow-Up Lanes" in doc
    assert "https://github.com/saagpatel/MCPAudit/issues/59" in doc
    assert "https://github.com/saagpatel/MCPAudit/issues/60" in doc
    assert "https://github.com/saagpatel/MCPAudit/issues/61" in doc
    assert "External Field Reports" in doc
    assert "docs/FIELD-REPORTS.md" in doc
    assert "docs/FEEDBACK-TO-FIXTURES.md" in readme


def test_field_report_template_collects_config_only_external_evidence() -> None:
    text = FIELD_REPORT_TEMPLATE.read_text()

    assert "Redacted field report" in text
    assert FIELD_REPORT_COMMAND in text
    assert "`--redact` scrubs hostname" in text
    assert "MCPAudit version" in text
    assert "Approximate server count" in text
    assert "JSON/SARIF consumer compatibility check" in text
    assert "Dashboard or CI ingestion check" in text
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in text
    assert "## Activation path" in text
    assert "without synchronous maintainer help" in text
    assert "Approximate minutes" in text
    assert "## Seven-day repeat readback" in text
    assert "## Expected fixture value" in text
    assert "Beta-readiness evidence only" in text


def test_field_report_template_preserves_safety_boundary() -> None:
    text = FIELD_REPORT_TEMPLATE.read_text()

    assert "avoids spawning MCP servers" in text
    assert "contacting remote endpoints" in text
    assert "Do not include" in text
    assert "API keys, tokens, passwords" in text
    assert "internal hostnames" in text
    assert "private disclosure" in text
    assert "SECURITY.md" in text


def test_field_report_docs_pin_activation_and_repeat_claim_boundaries() -> None:
    field_doc = FIELD_REPORT_DOC.read_text()
    request_doc = FIELD_REPORT_REQUEST_DOC.read_text()
    field_contract = " ".join(field_doc.split())
    request_contract = " ".join(request_doc.split())

    assert FIELD_REPORT_COMMAND in field_doc
    assert FIELD_REPORT_COMMAND in request_doc
    assert "uvx may contact the configured Python package index" in field_contract
    assert "Package downloads are a distribution proxy" in field_contract
    assert "at least 6 of 10 participants complete safely and unassisted" in field_contract
    assert "at least 3 valid external reports" in field_contract
    assert "at least 2 participants repeat after 7 days" in field_contract
    assert "fewer than 3 participants complete" in field_contract
    assert "more than 2 participants cannot redact safely" in field_contract
    assert "require separate authority" in field_contract
    assert "Self-tests and CI never count" in field_contract
    assert "7-14 days" in request_contract
    assert "download-count proxy for adoption" in request_contract
    assert "`2.1.0`" not in field_doc
