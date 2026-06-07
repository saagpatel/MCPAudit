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
    "mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact"
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


def test_field_report_docs_track_external_intake_and_beta_bar() -> None:
    doc = FIELD_REPORT_DOC.read_text()
    beta = Path("docs/BETA-READINESS.md").read_text()
    beta_evidence = Path("docs/BETA-READINESS-EVIDENCE.md").read_text()
    feedback = FEEDBACK_DOC.read_text()
    request = FIELD_REPORT_REQUEST_DOC.read_text()
    roadmap = Path("docs/ROADMAP-NEXT.md").read_text()
    readme = Path("README.md").read_text()

    assert "## External Intake Path" in doc
    assert FIELD_REPORT_COMMAND in doc
    assert "`--redact` scrubs hostname" in doc
    assert "## Minimal Public Example" in doc
    assert "This is an example shape only, not an accepted external field report." in doc
    assert "server-01" in doc
    assert "package_runner_source_review" in doc
    assert "remote_endpoint" in doc
    assert "Fixture permission: yes" in doc
    assert ".github/ISSUE_TEMPLATE/field_report.md" in doc
    assert "## Fixture Acceptance Bar" in doc
    assert "at least two external redacted reports" in doc
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in doc
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in beta
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in beta_evidence
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in feedback
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in request
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in roadmap
    assert "https://github.com/saagpatel/MCPAudit/milestone/4" in readme
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in doc
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in beta
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in beta_evidence
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in feedback
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in roadmap
    assert "docs/EXTERNAL-FIELD-REPORT-REQUEST.md" in readme
    for issue_number in ("83", "84", "85"):
        issue_url = f"https://github.com/saagpatel/MCPAudit/issues/{issue_number}"
        assert issue_url in doc
        assert issue_url in beta
        assert issue_url in beta_evidence
        assert issue_url in feedback
        assert issue_url in request
        assert issue_url in roadmap
    assert "Ship `1.5.5` as polish instead of `1.6.0` or beta." in beta
    assert "dedicated public field-report issue template" in roadmap


def test_external_field_report_request_is_safe_and_actionable() -> None:
    text = FIELD_REPORT_REQUEST_DOC.read_text()

    assert FIELD_REPORT_COMMAND in text
    assert "`--redact` auto-scrubs" in text
    assert "does not spawn MCP servers or contact remote endpoints" in text
    assert "issues/new?template=field_report.md" in text
    assert "Do not include" in text
    assert "API keys, tokens, passwords" in text
    assert "internal hostnames" in text
    assert "Maintainer Triage" in text
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in text
    assert "Confirm it was produced with `scan --skip-connect`" in text
    assert "Do not change `risk_score.composite` from these reports alone" in text


def test_external_outreach_messages_are_safe_and_actionable() -> None:
    text = FIELD_REPORT_OUTREACH_DOC.read_text()
    readme = Path("README.md").read_text()
    field_reports = FIELD_REPORT_DOC.read_text()
    request = FIELD_REPORT_REQUEST_DOC.read_text()
    show_hn = SHOW_HN_DRAFT_DOC.read_text()
    trust_packet = MCP_TRUST_PACKET_DOC.read_text()

    assert "Direct Ask For First Tester" in text
    assert "Direct Ask For Second Tester" in text
    assert "Public Post" in text
    assert "scan --skip-connect" in text
    assert FIELD_REPORT_COMMAND in text
    assert FIELD_REPORT_COMMAND in readme
    assert FIELD_REPORT_COMMAND in field_reports
    assert FIELD_REPORT_COMMAND in request
    assert "should not spawn MCP servers or contact remote endpoints" in text
    assert "meaningfully different setup or consumer path" in text
    assert "credentials, private paths" in text
    for issue_number in ("83", "84", "85"):
        assert f"https://github.com/saagpatel/MCPAudit/issues/{issue_number}" in text
    assert "docs/EXTERNAL-OUTREACH-MESSAGES.md" in readme
    assert "docs/EXTERNAL-OUTREACH-MESSAGES.md" in field_reports
    assert "docs/EXTERNAL-OUTREACH-MESSAGES.md" in request
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in text
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in readme
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in request
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in show_hn
    assert "docs/FIELD-REPORTS.md#minimal-public-example" in trust_packet
    assert "`--redact` is live (1.13.1)." in show_hn
    assert "docs/MCP-TRUST-PACKET.md" in text
    assert "MCPAudit is the trust wedge" in text
    assert "mcpforge" in trust_packet
    assert "bridge-db" in trust_packet


def test_solo_evidence_is_documented_without_weakening_external_gate() -> None:
    text = SOLO_EVIDENCE_DOC.read_text()
    readme = Path("README.md").read_text()
    field_reports = FIELD_REPORT_DOC.read_text()
    beta_evidence = Path("docs/BETA-READINESS-EVIDENCE.md").read_text()
    request = FIELD_REPORT_REQUEST_DOC.read_text()

    assert "scan --skip-connect" in text
    assert "not external evidence" in text
    assert "does not close issues #83, #84, or #85" in text
    assert "Do not upload private local MCP configuration to CI" in text
    assert "credential values, private paths" in text
    assert "2026-05-10 Solo Config-Only Pass" in text
    assert "docs/SOLO-EVIDENCE.md" in readme
    assert "docs/SOLO-EVIDENCE.md" in field_reports
    assert "docs/SOLO-EVIDENCE.md" in beta_evidence
    assert "docs/SOLO-EVIDENCE.md" in request
