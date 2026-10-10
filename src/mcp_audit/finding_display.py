"""Shared teaching views over existing finding records; no discovery or execution."""

from __future__ import annotations

import shlex
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass

from pydantic import BaseModel
from rich.console import Console

from mcp_audit.models import AuditReport
from mcp_audit.taxonomy import config_health_rule_id, finding_copy, finding_url
from mcp_audit.terminal_text import terminal_safe


@dataclass(frozen=True)
class FindingView:
    rule_id: str
    server: str
    source: str
    config_path: str
    target: str
    evidence: str
    action: str
    config_pointer: str = ""


def _literal(value: str) -> str:
    return value.replace("⟦", "‹U+27E6›").replace("⟧", "‹U+27E7›")


def _view(
    finding: BaseModel,
    *,
    rule_id: str = "",
    server: str = "",
    source: str = "",
    config_path: str = "",
    config_pointer: str = "",
) -> FindingView:
    data: dict[str, object] = finding.model_dump(mode="json")

    def text(key: str) -> str:
        value = data.get(key)
        return _literal(value) if isinstance(value, str) else ""

    evidence = text("summary") or text("description") or text("evidence")
    raw_matched = data.get("matched_text")
    matched = _literal(raw_matched) if isinstance(raw_matched, str) else ""
    if matched:
        span = data.get("matched_span")
        if isinstance(span, list) and len(span) == 2:
            start, end = span
            if (
                isinstance(raw_matched, str)
                and isinstance(start, int)
                and isinstance(end, int)
                and 0 <= start < end <= len(raw_matched)
            ):
                matched = (
                    _literal(raw_matched[:start])
                    + "⟦"
                    + _literal(raw_matched[start:end])
                    + "⟧"
                    + _literal(raw_matched[end:])
                )
        evidence += f"\nMatched text: {matched}"
    for key in (
        "evidence",
        "leg1_contributors",
        "leg2_contributors",
        "leg3_contributors",
        "details",
        "collisions",
        "gained_categories",
        "gained_patterns",
    ):
        value = data.get(key)
        if isinstance(value, list) and value:
            evidence += f"\n{key}: {_literal(str(value))}"
    target = text("target_name") or text("tool_name") or text("name")
    if text("field_path"):
        target += f" | field: {text('field_path')}"
    return FindingView(
        rule_id or text("rule_id"),
        server or text("server_name"),
        source,
        config_path,
        target,
        evidence,
        text("remediation"),
        config_pointer,
    )


def finding_views(report: AuditReport) -> Iterator[FindingView]:
    """Adapt every core report finding, retaining its evidence and identity."""
    for finding in report.config_health_findings:
        audits = [
            audit
            for audit in report.audits
            if audit.server.name == finding.server_name
            and (not finding.config_paths or audit.server.config_path in finding.config_paths)
        ]
        paths = finding.config_paths or [audit.server.config_path for audit in audits]
        labels = list(
            dict.fromkeys(
                f"{audit.server.source_label} | identity: "
                f"{audit.server.client.value}:{audit.server.scope}:{audit.server.name}"
                for audit in audits
            )
        )
        yield _view(
            finding,
            rule_id=config_health_rule_id(finding.finding_type),
            source="; ".join(labels),
            config_path="; ".join(dict.fromkeys(paths)),
            config_pointer="; ".join(
                dict.fromkeys(audit.server.config_pointer or "unavailable" for audit in audits)
            ),
        )
    for audit in report.audits:
        server = audit.server
        findings: tuple[BaseModel, ...] = (
            *audit.permissions,
            *audit.capability_findings,
            *audit.annotation_findings,
            *audit.injection_findings,
            *audit.schema_findings,
            *audit.ssrf_findings,
            *audit.egress_findings,
            *audit.trifecta_findings,
            *audit.escalation_findings,
            *audit.provenance_findings,
            *audit.integrity_findings,
            *audit.package_verify_findings,
            *audit.artifact_verify_findings,
            *audit.pin_integrity_findings,
            *audit.protocol_findings,
        )
        for record in findings:
            yield _view(
                record,
                server=server.name,
                source=f"{server.source_label} | identity: "
                f"{server.client.value}:{server.scope}:{server.name}",
                config_path=server.config_path,
                config_pointer=server.config_pointer or "",
            )
        for drift in audit.drift_findings:
            yield _view(
                drift,
                rule_id="MCP009",
                server=server.name,
                source=server.source_label,
                config_path=server.config_path,
                config_pointer=server.config_pointer or "",
            )
    for record in (*report.fleet_trifecta_findings, *report.shadowing_findings):
        yield _view(record, server="fleet")
    if report.policy_result is not None:
        for violation in report.policy_result.violations:
            yield _view(violation, rule_id="MCP010")


def render_finding_text(view: FindingView) -> str:
    """Render evidence and actionable, qualified copy in a narrow-terminal-friendly form."""
    copy = finding_copy(view.rule_id)
    lines = [f"{view.rule_id}: {copy.title}"]
    if view.server:
        lines.append(f"Server/config entry: {_literal(view.server)}")
    if view.config_path:
        lines.append(f"Source: {_literal(view.source)} | config_path: {_literal(view.config_path)}")
        pointer = _literal(view.config_pointer) or "unavailable (legacy or unresolved entry)"
        lines.append(f"Config entry pointer: {pointer}")
    if view.target:
        lines.append(f"Target: {view.target}")
    lines.append(f"What we saw: {view.evidence or copy.what_we_saw}")
    lines.append(
        "Why it matters: " + " ".join(f"{index}. {step}" for index, step in enumerate(copy.why_it_matters, 1))
    )
    lines.append(f"How to fix ({copy.time_to_fix}): {copy.how_to_fix}")
    if view.action:
        lines.append(f"Specific action: {view.action}")
    if view.rule_id == config_health_rule_id("shell_wrapper_launch"):
        lines.append(
            "Manual step: inspect this entry's shell arguments. If a direct executable and argument list "
            "can express the intended launch, use those instead of a shell wrapper. Otherwise remove "
            "this entry temporarily and restart the client while you review the script."
        )
    if view.config_path and "; " not in view.config_path and _literal(view.config_path) == view.config_path:
        lines.append(
            f"Static recheck (runtime not checked): mcp-audit check --config {shlex.quote(view.config_path)}"
        )
    lines.append(f"How sure: {copy.how_sure}")
    lines.append(f"see: {finding_url(view.rule_id)}")
    return "\n".join(lines)


def print_finding(console: Console, view: FindingView) -> None:
    """Wrap teaching text without padding or cutting paths and matched words."""
    text = terminal_safe(render_finding_text(view)).plain
    lines = [
        wrapped
        for line in text.splitlines()
        for wrapped in (
            textwrap.wrap(line, width=console.width, break_long_words=False, break_on_hyphens=False) or [""]
        )
    ]
    console.print(terminal_safe("\n".join(lines)), soft_wrap=True)
