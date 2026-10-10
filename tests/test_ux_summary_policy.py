"""Policy actions preserve distinct violations and their affected targets."""

from pathlib import Path

from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, CheckCoverage, ConfigHealthFinding, ConfigHealthSeverity
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.ux_summary import actions


def test_policy_actions_preserve_same_name_servers_in_distinct_configs() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/policy_failure_report.json").read_text()
    )
    original = report.audits[0]
    duplicate = original.model_copy(deep=True)
    duplicate.server.config_path = "/tmp/other-synthetic-config.json"
    report.audits.append(duplicate)
    report.policy_result = evaluate_policy(report, PolicyConfig(allow_servers=["allowed"]))
    violations = report.policy_result.violations
    assert len(violations) == 2
    assert violations[0].message == violations[1].message
    assert [v.audit_index for v in violations] == [0, 1]
    for candidate in (report, report.redacted(identifiers=True)):
        policy_actions = [action for action in actions(candidate) if action.sources == ["allow_servers"]]
        assert len(policy_actions) == 2


def test_policy_actions_retain_disallowed_servers_rules_and_tools() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/policy_failure_report.json").read_text()
    )
    template = report.audits[0]
    report.audits = []
    for name in ("alpha", "beta"):
        audit = template.model_copy(deep=True)
        audit.server.name = name
        audit.permissions.append(audit.permissions[0].model_copy(update={"tool_name": "other_shell"}))
        report.audits.append(audit)
    report.servers_discovered = report.servers_connected = 2
    report.coverage["metadata"] = CheckCoverage(state="complete", reason="synthetic fixture completed")
    report.coverage["injection"] = CheckCoverage(state="not_run", reason="synthetic fixture skipped")
    report.policy_result = evaluate_policy(
        report,
        PolicyConfig(allow_servers=["allowed"], max_risk=7, fail_on_severity="high", fail_on_coverage=True),
    )
    violations = report.policy_result.violations
    # Coverage has multiple messages for one rule; permissions repeat a message
    # on distinct tools. Neither should disappear behind the shared remediation.
    assert {v.rule for v in violations} == {
        "allow_servers",
        "max_risk",
        "fail_on.severity",
        "fail_on.coverage",
    }
    for candidate in (report, report.redacted(identifiers=True)):
        assert candidate.policy_result is not None
        policy_actions = [
            action
            for action in actions(candidate)
            if any("Review this violation against your selected policy." in step for step in action.steps)
        ]
        # One policy action per actual server, plus each unbound coverage row.
        assert len(policy_actions) == 2 + sum(v.audit_index is None for v in violations)
        for violation in candidate.policy_result.violations:
            matches = [
                action
                for action in policy_actions
                if violation.rule in action.sources
                and any(
                    violation.message in step
                    and all(
                        target in step for target in (violation.server_name, violation.tool_name) if target
                    )
                    for step in action.steps
                )
            ]
            assert len(matches) == 1
            ranks = {"low": 0, "medium": 1, "high": 2}
            assert ranks[matches[0].severity] >= ranks[violation.severity]
        generator = HtmlReportGenerator()
        html = generator.generate(candidate)
        for action in policy_actions:
            assert generator._esc(action.title) in html
            for step in action.steps:
                assert generator._esc(step) in html


def test_config_health_policy_binds_same_name_servers_by_source_path() -> None:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/policy_failure_report.json").read_text()
    )
    first = report.audits[0]
    second = first.model_copy(deep=True)
    first.server.config_path = "/Users/synthetic-user-a/mcp.json"
    second.server.config_path = "/Users/synthetic-user-b/mcp.json"
    report.audits = [first, second]
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="toy",
            severity=ConfigHealthSeverity.HIGH,
            server_name=audit.server.name,
            summary=f"Review {audit.server.config_path}",
            remediation="Review config.",
            config_paths=[audit.server.config_path],
        )
        for audit in report.audits
    ]
    report.policy_result = evaluate_policy(
        report,
        PolicyConfig(
            allow_servers=["allowed"],
            fail_on_config_health_severity="high",
        ),
    )
    for candidate in (report, report.redacted(identifiers=True)):
        policy_actions = [a for a in actions(candidate) if "fail_on.config_health" in a.sources]
        assert len(policy_actions) == 2
        assert all("allow_servers" in action.sources for action in policy_actions)
        assert all(len(action.steps) == 2 for action in policy_actions)
