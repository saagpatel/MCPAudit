"""Presentation-only actions and finding-class grades; numeric scores stay unchanged."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from mcp_audit.models import ReviewAction as Action
from mcp_audit.models import ReviewGrade, ReviewSummary

__all__ = ["Action", "actions", "grade"]

if TYPE_CHECKING:
    from mcp_audit.models import AuditReport, ServerAudit


class _Finding(Protocol):
    @property
    def rule_id(self) -> str: ...

    @property
    def severity(self) -> str: ...

    @property
    def title(self) -> str: ...

    @property
    def remediation(self) -> str: ...


class _Outbound(_Finding, Protocol):
    @property
    def target_type(self) -> str: ...

    @property
    def target_name(self) -> str: ...


def action_owner(audit: ServerAudit) -> tuple[str, str, str, str]:
    """Raw identity used only while computing the unredacted snapshot."""
    server = audit.server
    return server.client.value, server.scope, server.config_path, server.name


def actions(report: AuditReport) -> list[Action]:
    return report.ensure_review_summary().actions


def grade(report: AuditReport) -> str | None:
    return report.ensure_review_summary().grade


def compute_summary(report: AuditReport) -> ReviewSummary:
    """Merge overlapping detector advice by server identity and action family.

    All source rules and remediation steps survive deduplication. The audit log
    retains the original rows and evidence, including lower-priority findings.
    """
    grouped: dict[tuple[str, str], Action] = {}
    ranks = {"high": 0, "medium": 1, "low": 2}
    owners: dict[tuple[str, ...], str] = {}

    def owner_id(identity: tuple[str, ...]) -> str:
        return owners.setdefault(identity, f"owner-{len(owners) + 1:04d}")

    def add(owner: str, family: str, severity: str, title: str, step: str, source: str) -> None:
        key = (owner, family)
        if key not in grouped and step and family != "policy":
            key = next(
                (
                    existing
                    for existing, action in grouped.items()
                    if existing[0] == owner and step in action.steps
                ),
                key,
            )
        if key not in grouped:
            grouped[key] = Action(
                identity=f"action-{len(grouped) + 1:04d}",
                owner=owner,
                severity=severity,
                title=title,
            )
        action = grouped[key]
        if ranks.get(severity, 2) < ranks.get(action.severity, 2):
            action.severity = severity
        if step and step not in action.steps:
            action.steps.append(step)
        if source and source not in action.sources:
            action.sources.append(source)

    for audit in report.audits:
        server = audit.server
        owner = owner_id(("server", *action_owner(audit)))
        where = f"{server.name} ({server.client.value}, {server.config_path})"
        permission_findings: list[_Finding] = [*audit.permissions, *audit.capability_findings]
        for finding in permission_findings:
            add(
                owner,
                finding.rule_id,
                finding.severity,
                f"Review what {server.name} can do",
                finding.remediation,
                f"{finding.rule_id}: {where}",
            )
        for injection in audit.injection_findings:
            add(
                owner,
                "instructions",
                injection.severity.value,
                f"Review hidden instructions on {server.name}",
                injection.remediation,
                f"{injection.rule_id}: {where}",
            )
        outbound_findings: list[_Outbound] = [*audit.ssrf_findings, *audit.egress_findings]
        for outbound in outbound_findings:
            add(
                owner,
                f"outbound:{outbound.target_type}:{outbound.target_name}",
                outbound.severity,
                f"Restrict where {server.name} can send requests",
                outbound.remediation,
                f"{outbound.rule_id}: {where}",
            )
        other_findings: list[_Finding] = [
            *audit.annotation_findings,
            *audit.trifecta_findings,
            *audit.escalation_findings,
            *audit.provenance_findings,
            *audit.integrity_findings,
            *audit.package_verify_findings,
            *audit.artifact_verify_findings,
        ]
        for finding_with_rule in other_findings:
            add(
                owner,
                finding_with_rule.rule_id,
                finding_with_rule.severity,
                f"{finding_with_rule.title}: {server.name}",
                finding_with_rule.remediation,
                f"{finding_with_rule.rule_id}: {where}",
            )
        for drift in audit.drift_findings:
            add(
                owner,
                "drift",
                drift.severity,
                f"Review changes on {server.name}",
                drift.remediation or "Compare the changed surface with your reviewed baseline.",
                f"{drift.target_name}: {where}",
            )
        if audit.annotations_missing:
            add(
                owner,
                "annotations_missing",
                "low",
                f"{server.name} has missing tool labels",
                "Ask the server author to describe read-only and destructive behavior.",
                where,
            )
    for health in report.config_health_findings:
        add(
            owner_id(("config", health.server_name or "", *health.config_paths)),
            f"{health.server_name}:{health.finding_type}",
            health.severity.value,
            health.summary,
            health.remediation,
            ", ".join(health.config_paths),
        )
    fleet_findings: list[_Finding] = [*report.fleet_trifecta_findings, *report.shadowing_findings]
    for fleet in fleet_findings:
        add(
            owner_id(("fleet",)), fleet.rule_id, fleet.severity, fleet.title, fleet.remediation, fleet.rule_id
        )
    if report.policy_result:
        for index, violation in enumerate(report.policy_result.violations):
            targets = [target for target in (violation.server_name, violation.tool_name) if target]
            audit_index = violation.audit_index
            matches = [
                i for i, audit in enumerate(report.audits) if audit.server.name == violation.server_name
            ]
            if audit_index is None and len(matches) == 1:
                audit_index = matches[0]
            if audit_index is not None and 0 <= audit_index < len(report.audits):
                owner = owner_id(("server", *action_owner(report.audits[audit_index])))
            else:
                # Legacy/ambiguous rows have no source identity: preserve each.
                owner = owner_id(("policy-row", str(index)))
            message = violation.message + (f" ({', '.join(targets)})" if targets else "")
            add(
                owner,
                "policy",
                violation.severity,
                message,
                message + " Review this violation against your selected policy.",
                violation.rule,
            )
    findings = sorted(grouped.values(), key=lambda action: ranks.get(action.severity, 2))
    for index, action in enumerate(findings, start=1):
        action.identity = f"action-{index:04d}"
    counts = {severity: sum(action.severity == severity for action in findings) for severity in ranks}
    return ReviewSummary(
        actions=findings,
        action_counts=counts,
        action_count=len(findings),
        grade=_compute_grade(report, findings),
        review_minutes=len(findings) * 5,
    )


def _compute_grade(report: AuditReport, findings: list[Action]) -> ReviewGrade | None:
    """D6 rubric, qualified by metadata completion; never read a risk score.

    Incomplete/legacy reports get no letter. Confirmed shell launch means a
    shell-wrapper config finding, distinct from a metadata capability hint.
    """
    if report.connection_mode.value != "attempted" or not report.audits:
        return None
    metadata = report.coverage.get("metadata")
    if metadata is None or metadata.state != "complete":
        return None
    if any(audit.injection_findings for audit in report.audits) or any(
        finding.finding_type in {"secret_in_config", "shell_wrapper_launch"}
        for finding in report.config_health_findings
    ):
        return "F"
    fixes = sum(action.severity == "high" for action in findings)
    chain_and_shell = any(
        audit.trifecta_findings
        and (
            any(f.category.value == "shell_execution" for f in audit.permissions)
            or any(f.category.value == "shell_execution" for f in audit.capability_findings)
        )
        for audit in report.audits
    )
    if fixes >= 2 or chain_and_shell:
        return "D"
    if fixes == 1:
        return "C"
    if any(action.severity == "medium" for action in findings):
        return "B"
    return "A"
