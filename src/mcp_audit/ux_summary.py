"""Presentation-only actions and finding-class grades; numeric scores stay unchanged."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from mcp_audit.models import AuditReport, ServerAudit


@dataclass
class Action:
    severity: str
    title: str
    steps: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


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


def action_owner(audit: ServerAudit) -> str:
    """Use the pre-redaction identity when the report carries one."""
    server = audit.server
    return audit.presentation_id or f"{server.client.value}:{server.scope}:{server.config_path}:{server.name}"


def actions(report: AuditReport) -> list[Action]:
    """Merge overlapping detector advice by server identity and action family.

    All source rules and remediation steps survive deduplication. The audit log
    retains the original rows and evidence, including lower-priority findings.
    """
    grouped: dict[tuple[str, str], Action] = {}
    ranks = {"high": 0, "medium": 1, "low": 2}

    def add(owner: str, family: str, severity: str, title: str, step: str, source: str) -> None:
        key = (owner, family)
        if key not in grouped and step:
            key = next(
                (
                    existing
                    for existing, action in grouped.items()
                    if existing[0] == owner and step in action.steps
                ),
                key,
            )
        if key not in grouped:
            grouped[key] = Action(severity, title)
        action = grouped[key]
        if ranks.get(severity, 2) < ranks.get(action.severity, 2):
            action.severity = severity
        if step and step not in action.steps:
            action.steps.append(step)
        if source and source not in action.sources:
            action.sources.append(source)

    for audit in report.audits:
        server = audit.server
        owner = action_owner(audit)
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
            "|".join(health.config_paths),
            f"{health.server_name}:{health.finding_type}",
            health.severity.value,
            health.summary,
            health.remediation,
            ", ".join(health.config_paths),
        )
    fleet_findings: list[_Finding] = [*report.fleet_trifecta_findings, *report.shadowing_findings]
    for fleet in fleet_findings:
        add("fleet", fleet.rule_id, fleet.severity, fleet.title, fleet.remediation, fleet.rule_id)
    policy_actions: list[Action] = []
    if report.policy_result:
        for violation in report.policy_result.violations:
            targets = [target for target in (violation.server_name, violation.tool_name) if target]
            # Policy rows carry names, not full server identities; merging even
            # identical messages could hide violations from different configs.
            policy_actions.append(
                Action(
                    severity=violation.severity,
                    title=violation.message + (f" ({', '.join(targets)})" if targets else ""),
                    steps=["Review this violation against your selected policy."],
                    sources=[violation.rule],
                )
            )
    return sorted([*grouped.values(), *policy_actions], key=lambda action: ranks.get(action.severity, 2))


def grade(report: AuditReport) -> str | None:
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
    fixes = sum(action.severity == "high" for action in actions(report))
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
    if any(action.severity == "medium" for action in actions(report)):
        return "B"
    return "A"
