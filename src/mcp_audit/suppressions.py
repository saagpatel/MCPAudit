"""Visible finding exceptions without mutating evidence, scores, or coverage."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mcp_audit.models import AuditReport, ScanWarning, SuppressedFinding
from mcp_audit.redaction import redacted_excerpt

_AUDIT_GROUPS = (
    "permissions",
    "annotation_findings",
    "capability_findings",
    "injection_findings",
    "ssrf_findings",
    "egress_findings",
    "trifecta_findings",
    "escalation_findings",
    "provenance_findings",
    "integrity_findings",
    "package_verify_findings",
    "artifact_verify_findings",
    "drift_findings",
)
_FLEET_GROUPS = ("fleet_trifecta_findings", "shadowing_findings")


def validate_ignore_rule(rule: str) -> str:
    """Only finding rules are suppressible; policy and coverage are never findings here."""
    from mcp_audit.taxonomy import FINDING_COPY

    if rule not in FINDING_COPY or rule == "MCP010":
        raise ValueError("ignore.rule must be a known MCP finding ID other than MCP010")
    return rule


class IgnoreEntry(BaseModel):
    """A reviewed exception targeting exact names or the explicit wildcard '*'."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rule: str
    server: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    expires: date | None = None

    @field_validator("rule")
    @classmethod
    def known_rule(cls, value: str) -> str:
        return validate_ignore_rule(value)

    @field_validator("expires", mode="before")
    @classmethod
    def expiry_date(cls, value: object) -> object:
        if value is None or type(value) is date:
            return value
        if isinstance(value, str):
            return date.fromisoformat(value)
        raise ValueError("ignore.expires must be an ISO date (YYYY-MM-DD)")


@dataclass(frozen=True)
class _Finding:
    path: str
    rule: str
    severity: str
    targets: tuple[tuple[str, str], ...]


def _finding(path: str, item: BaseModel, server: str = "") -> _Finding:
    data: dict[str, object] = item.model_dump(mode="json")
    rule = data.get("rule_id", "MCP009")
    severity = data.get("severity", "medium")
    target = data.get("target_name", data.get("tool_name", ""))
    targets = [(server, target if isinstance(target, str) else "")]
    for key in ("collisions", "leg1_contributors", "leg2_contributors", "leg3_contributors"):
        contributors = data.get(key)
        if isinstance(contributors, list):
            for pair in contributors:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    name, tool = pair
                    if isinstance(name, str) and isinstance(tool, str):
                        targets.append((name, tool))
    return _Finding(path, str(rule), str(severity), tuple(targets))


def _findings(report: AuditReport) -> Iterator[_Finding]:
    for index, audit in enumerate(report.audits):
        for group in _AUDIT_GROUPS:
            items: Sequence[BaseModel] = getattr(audit, group)
            for offset, item in enumerate(items):
                yield _finding(f"/audits/{index}/{group}/{offset}", item, audit.server.name)
    for group in _FLEET_GROUPS:
        items = getattr(report, group)
        for offset, item in enumerate(items):
            yield _finding(f"/{group}/{offset}", item)


def apply_suppressions(
    report: AuditReport,
    entries: Sequence[IgnoreEntry] = (),
    *,
    cli_rules: Sequence[str] = (),
    cli_reason: str | None = None,
) -> None:
    """Annotate a fresh report once; expired entries and unreasoned HIGHs stay active."""
    if not entries and not cli_rules:
        return
    for rule in cli_rules:
        validate_ignore_rule(rule)
    today = report.scan_timestamp.date()
    refused: set[str] = set()
    existing = {item.finding_path for item in report.suppressed}
    for finding in _findings(report):
        if finding.path in existing:
            continue
        matched = next(
            (
                entry
                for entry in entries
                if entry.rule == finding.rule
                and (entry.expires is None or entry.expires >= today)
                and any(
                    (entry.server == "*" or entry.server == server)
                    and (entry.tool == "*" or entry.tool == tool)
                    for server, tool in finding.targets
                )
            ),
            None,
        )
        source: Literal["config", "cli"] = "config"
        reason = matched.reason if matched else None
        expires = matched.expires if matched else None
        if matched is None and finding.rule in cli_rules:
            source = "cli"
            reason = cli_reason.strip() if cli_reason else ""
            if finding.severity == "high" and not reason:
                refused.add(finding.rule)
                continue
            reason = reason or "One-run --ignore requested by operator"
        if reason:
            report.suppressed.append(
                SuppressedFinding(
                    finding_path=finding.path,
                    rule_id=finding.rule,
                    reason=redacted_excerpt(reason, 0, len(reason), max_length=512),
                    source=source,
                    expires=expires,
                )
            )
    if refused:
        report.warnings.append(
            ScanWarning(
                code="ignore_reason_required",
                message="HIGH findings remain active; --ignore-reason is required for: "
                + ", ".join(sorted(refused)),
            )
        )


def unsuppressed_report(report: AuditReport) -> AuditReport:
    """Return a policy-only view. Never filter coverage, diagnostics, or numeric scores."""
    valid = {f.path: f.rule for f in _findings(report)}
    ignored = {
        item.finding_path
        for item in report.suppressed
        if item.reason.strip()
        and valid.get(item.finding_path) == item.rule_id
        and (item.expires is None or item.expires >= report.scan_timestamp.date())
    }
    audits = []
    for index, audit in enumerate(report.audits):
        updates: dict[str, object] = {}
        for group in _AUDIT_GROUPS:
            items: Sequence[BaseModel] = getattr(audit, group)
            updates[group] = [
                item
                for offset, item in enumerate(items)
                if f"/audits/{index}/{group}/{offset}" not in ignored
            ]
        audits.append(audit.model_copy(update=updates))
    report_updates: dict[str, object] = {"audits": audits}
    for group in _FLEET_GROUPS:
        items = getattr(report, group)
        report_updates[group] = [
            item for offset, item in enumerate(items) if f"/{group}/{offset}" not in ignored
        ]
    return report.model_copy(update=report_updates)


def suppression_summary(report: AuditReport) -> str:
    """Keep every exception visible alongside coverage, including its reason."""
    return f"Suppressed: {len(report.suppressed)}" + (
        " ("
        + "; ".join(f"{item.rule_id} at {item.finding_path}: {item.reason}" for item in report.suppressed)
        + ")"
        if report.suppressed
        else ""
    )
