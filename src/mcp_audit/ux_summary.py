"""Presentation-only actions and finding-class grades; numeric scores stay unchanged."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel

from mcp_audit.coverage import missing_checks
from mcp_audit.models import ReviewAction as Action
from mcp_audit.models import (
    ReviewActionDisplay,
    ReviewGrade,
    ReviewSummary,
    ShadowingFinding,
    TrifectaFinding,
)

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


def _display(
    finding: object, audits: list[ServerAudit], sources: tuple[str, ...] = ()
) -> ReviewActionDisplay:
    from mcp_audit.terminal_summary import _action

    assert isinstance(finding, BaseModel)
    return _action(finding, audits, sources)


def _manual_display(title: str, step: str, rule: str, audits: list[ServerAudit]) -> ReviewActionDisplay:
    from mcp_audit.terminal_summary import _identity

    return ReviewActionDisplay(
        severity="low",  # The canonical action supplies severity when rendered.
        title=title,
        consequence="Review the recorded finding before use.",
        step=step,
        sources=tuple(dict.fromkeys(a.server.config_path for a in audits)),
        identities=tuple(_identity(a) for a in audits),
        rule=rule,
    )


def compute_summary(report: AuditReport) -> ReviewSummary:
    """Merge overlapping detector advice by server identity and action family.

    All source rules and remediation steps survive deduplication. The audit log
    retains the original rows and evidence, including lower-priority findings.
    """
    grouped: dict[tuple[str, str], Action] = {}
    ranks = {"high": 0, "medium": 1, "low": 2}
    owners: dict[tuple[str, ...], str] = {}
    finding_severities: dict[tuple[str, str, str], str] = {}

    def owner_id(identity: tuple[str, ...]) -> str:
        return owners.setdefault(identity, f"owner-{len(owners) + 1:04d}")

    def add(
        owner: str,
        family: str,
        severity: str,
        title: str,
        step: str,
        source: str,
        display: ReviewActionDisplay | None = None,
        finding: object | None = None,
        *,
        merge_steps: bool = True,
    ) -> None:
        # Grade distinct finding rows on their raw owner, before advice is folded.
        if finding is not None:
            assert isinstance(finding, BaseModel)
            finding_kind = type(finding).__name__
            finding_key = finding.model_dump_json()
        else:
            finding_kind = "manual"
            finding_key = family
        finding_severities[(owner, finding_kind, finding_key)] = severity
        key = (owner, family)
        if merge_steps and key not in grouped and step and family != "policy":
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
                terminal=display,
            )
        action = grouped[key]
        if ranks.get(severity, 2) < ranks.get(action.severity, 2):
            action.severity = severity
        if step and step not in action.steps:
            action.steps.append(step)
        if source and source not in action.sources:
            action.sources.append(source)
        if display is not None and action.terminal is not None:
            current = action.terminal
            action.terminal = current.model_copy(
                update={
                    "severity": action.severity,
                    "flags": tuple(dict.fromkeys((*current.flags, *display.flags))),
                    "connected": current.connected or display.connected,
                    "step": " ".join(dict.fromkeys((current.step, display.step))),
                }
            )

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
                _display(finding, [audit]),
                finding,
            )
        for injection in audit.injection_findings:
            add(
                owner,
                "instructions",
                injection.severity.value,
                f"Review hidden instructions on {server.name}",
                injection.remediation,
                f"{injection.rule_id}: {where}",
                _display(injection, [audit]),
                injection,
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
                _display(outbound, [audit]),
                outbound,
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
                _display(finding_with_rule, [audit]),
                finding_with_rule,
            )
        for drift in audit.drift_findings:
            add(
                owner,
                "drift",
                drift.severity,
                f"Review changes on {server.name}",
                drift.remediation or "Compare the changed surface with your reviewed baseline.",
                f"{drift.target_name}: {where}",
                _display(drift, [audit]),
                drift,
            )
        if audit.annotations_missing:
            add(
                owner,
                "annotations_missing",
                "low",
                f"{server.name} has missing tool labels",
                "Ask the server author to describe read-only and destructive behavior.",
                where,
                _manual_display(
                    f"{server.name} has missing tool labels",
                    "Ask the server author to describe read-only and destructive behavior.",
                    "MCP005",
                    [audit],
                ),
            )
    for health in report.config_health_findings:
        add(
            owner_id(("config", health.server_name or "", *health.config_paths)),
            f"{health.server_name}:{health.finding_type}",
            health.severity.value,
            health.summary,
            health.remediation,
            ", ".join(health.config_paths),
            _display(
                health,
                [
                    audit
                    for audit in report.audits
                    if (health.server_name is None or audit.server.name == health.server_name)
                    and (not health.config_paths or audit.server.config_path in health.config_paths)
                ],
                tuple(health.config_paths),
            ),
            health,
            merge_steps=False,
        )
    fleet_findings: list[_Finding] = [*report.fleet_trifecta_findings, *report.shadowing_findings]
    for fleet in fleet_findings:
        if isinstance(fleet, TrifectaFinding):
            names = {
                name
                for leg in (fleet.leg1_contributors, fleet.leg2_contributors, fleet.leg3_contributors)
                for name, _ in leg
            }
        else:
            assert isinstance(fleet, ShadowingFinding)
            names = {name for name, _ in fleet.collisions}
        add(
            owner_id(("fleet",)),
            fleet.rule_id,
            fleet.severity,
            fleet.title,
            fleet.remediation,
            fleet.rule_id,
            _display(fleet, [audit for audit in report.audits if audit.server.name in names]),
            fleet,
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
                _manual_display(
                    message,
                    message + " Review this violation against your selected policy.",
                    violation.rule,
                    [report.audits[audit_index]]
                    if audit_index is not None and 0 <= audit_index < len(report.audits)
                    else [],
                ),
                violation,
            )
    findings = sorted(grouped.values(), key=lambda action: ranks.get(action.severity, 2))
    cards: dict[tuple[tuple[str, ...], tuple[str, ...]], str] = {}
    for index, action in enumerate(findings, start=1):
        action.identity = f"action-{index:04d}"
        if action.terminal is not None:
            action.terminal = action.terminal.model_copy(update={"severity": action.severity})
            key = (action.terminal.identities, action.terminal.sources)
            # Preserve P2-2's visual card folding, bound before identifiers can collide.
            action.card_group = cards.setdefault(key, f"card-{len(cards) + 1:04d}")
    counts = {severity: sum(action.severity == severity for action in findings) for severity in ranks}
    return ReviewSummary(
        actions=findings,
        action_counts=counts,
        action_count=len(findings),
        grade=_compute_grade(report, list(finding_severities.values())),
        review_minutes=len(findings) * 5,
    )


_CORE = ("config_health", "metadata", "permissions", "capabilities")
_STRUCTURAL_INJECTION = {"hidden_directive", "unicode_direction", "OBFUSCATED_METADATA"}


def _compute_grade(report: AuditReport, severities: list[str]) -> ReviewGrade | None:
    """D6 rubric, qualified by metadata completion; never read a risk score.

    Incomplete/legacy reports get no letter. Confirmed shell launch means a
    shell-wrapper config finding, distinct from a metadata capability hint.
    """
    if report.connection_mode.value != "attempted" or not report.audits:
        return None
    if any(report.coverage.get(key) is None or report.coverage[key].state != "complete" for key in _CORE):
        return None
    if any(audit.connection_status != "connected" for audit in report.audits):
        return None
    if missing_checks(report.coverage) or any(
        entry.state in {"partial", "not_run"} for entry in report.coverage.values()
    ):
        return None
    if report.warnings:
        return None
    # D4: phrase-only instruction text is never decisive; structural patterns are.
    if any(
        finding.pattern_name in _STRUCTURAL_INJECTION
        for audit in report.audits
        for finding in audit.injection_findings
    ) or any(
        finding.finding_type in {"secret_in_config", "shell_wrapper_launch"}
        for finding in report.config_health_findings
    ):
        return "F"
    fixes = severities.count("high")
    chain = bool(report.fleet_trifecta_findings) or any(audit.trifecta_findings for audit in report.audits)
    shell = any(
        any(f.category.value == "shell_execution" for f in audit.permissions)
        or any(f.category.value == "shell_execution" for f in audit.capability_findings)
        for audit in report.audits
    )
    chain_and_shell = chain and shell
    if fixes >= 2 or chain_and_shell:
        return "D"
    if fixes == 1:
        return "C"
    if "medium" in severities:
        return "B"
    return "A"
