"""Single-file HTML report generator for mcp-audit.

Produces a self-contained, shareable HTML document from an ``AuditReport`` —
inline CSS, no JavaScript, no external resources, so it renders offline and can
be emailed or attached to a ticket as-is.

Security notes:
  * The report is built from a redacted copy of the audit (``AuditReport.redacted``), so
    likely credential values are removed by best-effort pattern matching.
  * EVERY dynamic value is HTML-escaped via ``html.escape``. Tool descriptions
    are attacker-influenceable and may contain ``<script>`` or other markup; the
    report must never become an XSS vector when opened in a browser.
"""

from __future__ import annotations

import re
from enum import Enum
from html import escape
from typing import Literal, get_args, get_origin

from pydantic import BaseModel

from mcp_audit.coverage import missing_checks
from mcp_audit.finding_display import finding_views, render_finding_text
from mcp_audit.models import AuditReport, PermissionCategory, ReviewSummary, ServerAudit
from mcp_audit.normalize import render_invisibles
from mcp_audit.redaction import redact_identifiers
from mcp_audit.taxonomy import finding_url, format_rule_of_two
from mcp_audit.terminal_text import strip_controls
from mcp_audit.ux_summary import Action

_SEVERITY_CLASS = {
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
}


def _has_literal(annotation: object) -> bool:
    return get_origin(annotation) is Literal or any(_has_literal(member) for member in get_args(annotation))


def _hide_text(value: str, hostname: str) -> str:
    if hostname:
        value = re.sub(r"(?<![\w-])" + re.escape(hostname) + r"(?![\w-])", "<redacted-host>", value)
    hidden = redact_identifiers(value)
    assert isinstance(hidden, str)
    return hidden


def _hide_identifiers(value: object, hostname: str) -> object:
    """Scrub free text on a copy, preserving typed enums and literal vocabulary."""
    if isinstance(value, BaseModel):
        return value.model_copy(
            update={
                name: _hide_identifiers(getattr(value, name), hostname)
                for name, field in type(value).model_fields.items()
                if not _has_literal(field.annotation)
                and name
                not in {
                    "identity",
                    "owner",
                    "grade",
                    "severity",
                    "connection_status",
                    "finding_type",
                    "code",
                    "check",
                }
            }
        )
    if isinstance(value, str) and not isinstance(value, Enum):
        return _hide_text(value, hostname)
    if isinstance(value, list):
        return [_hide_identifiers(item, hostname) for item in value]
    if isinstance(value, tuple):
        return tuple(_hide_identifiers(item, hostname) for item in value)
    if isinstance(value, dict):
        return {key: _hide_identifiers(item, hostname) for key, item in value.items()}
    return value


_STYLE = """
:root { color-scheme: light dark; --bg: #fafafa; --card: #fff; --ink: #1a1a1a;
        --muted: #595959; --line: #b8b8b8; --head: #f2f2f2;
        --high-bg: #fde7e7; --high: #a01313; --medium-bg: #fdf3e0; --medium: #795000;
        --low-bg: #e8f0fe; --low: #2a51a8; --ok-bg: #e6f5ea; --ok: #17612c; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0 auto; max-width: 1100px; padding: 2rem; line-height: 1.5;
       color: var(--ink); background: var(--bg); overflow-wrap: anywhere; }
h1 { font-size: 1.6rem; margin: 0 0 0.25rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 0.75rem; border-bottom: 2px solid var(--line);
     padding-bottom: 0.25rem; }
h3 { font-size: 1rem; margin: 0.75rem 0 0.5rem; }
.subtitle, .muted, .empty, footer { color: var(--muted); }
.subtitle { margin: 0 0 1.5rem; font-size: 0.9rem; }
.hero { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 1.5rem;
        align-items: center; padding: 1.5rem; background: var(--card);
        border: 1px solid var(--line); border-radius: 12px; }
.grade { font-size: 3rem; font-weight: 800; text-align: center; }
.grade.preview { font-size: 1.5rem; }
.caveat { margin-bottom: 0; color: var(--muted); font-size: 0.9rem; }
.summary { display: flex; flex-wrap: wrap; gap: 1rem; margin: 1rem 0; }
.checked-strip, .coverage-incomplete { margin: 1rem 0; padding: 0.65rem 0.85rem;
                 border: 1px solid var(--line); border-radius: 6px; background: var(--card); }
.coverage-incomplete { background: var(--medium-bg); color: var(--medium); }
.coverage-item { margin: 0.2rem 0; }
.stat { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
        padding: 0.75rem 1rem; min-width: 0; }
.stat .num { font-size: 1.5rem; font-weight: 700; }
.stat .label { font-size: 0.75rem; color: var(--muted); }
.table-scroll { max-width: 100%; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem;
        background: var(--card); font-size: 0.88rem; }
th, td { text-align: left; padding: 0.45rem 0.6rem; border: 1px solid var(--line);
         vertical-align: top; }
th { background: var(--head); font-weight: 600; }
code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 0.85em; }
.server, .action, details { background: var(--card); border: 1px solid var(--line);
          border-radius: 8px; padding: 1rem; margin: 1rem 0; min-width: 0; }
summary { cursor: pointer; font-weight: 600; }
.server-head { display: flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
         font-size: 0.8rem; font-weight: 600; }
.sev-high { background: var(--high-bg); color: var(--high); }
.sev-medium { background: var(--medium-bg); color: var(--medium); }
.sev-low { background: var(--low-bg); color: var(--low); }
.ok { background: var(--ok-bg); color: var(--ok); }
.empty { font-style: italic; margin: 0.25rem 0 1rem; }
.policy-pass { color: var(--ok); font-weight: 600; }
.policy-fail { color: var(--high); font-weight: 600; }
footer { margin-top: 2.5rem; font-size: 0.85rem; }
@media (max-width: 640px) {
  body { padding: 1rem; }
  .hero { grid-template-columns: minmax(0, 1fr); padding: 1rem; }
  .grade { text-align: left; }
  .summary { display: grid; grid-template-columns: minmax(0, 1fr); }
}
.finding-explanation { white-space: pre-wrap; overflow-wrap: anywhere; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161616; --card: #1f1f1f; --ink: #e6e6e6; --muted: #b5b5b5;
          --line: #696969; --head: #262626; --high-bg: #451f24; --high: #ffb4b4;
          --medium-bg: #3c301d; --medium: #f5cf88; --low-bg: #1e304d; --low: #bad1ff;
          --ok-bg: #1b3525; --ok: #a2dfb5; }
}
"""


class HtmlReportGenerator:
    """Converts an ``AuditReport`` into a single self-contained HTML string."""

    def generate(self, report: AuditReport, *, show_host: bool = False) -> str:
        """Return the full HTML document. Caller writes it to disk."""
        report = report.redacted()
        summary = report.ensure_review_summary()
        findings = summary.actions
        if not show_host:
            findings = [
                Action(
                    identity=action.identity,
                    owner=action.owner,
                    severity=action.severity,
                    title=_hide_text(action.title, report.hostname),
                    steps=[_hide_text(step, report.hostname) for step in action.steps],
                    sources=[_hide_text(source, report.hostname) for source in action.sources],
                )
                for action in findings
            ]
            hidden = _hide_identifiers(report, report.hostname)
            assert isinstance(hidden, AuditReport)
            report = hidden
        parts: list[str] = [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>mcp-audit report</title>",
            f"<style>{_STYLE}</style>",
            "</head><body>",
            "<h1>MCP Permission Audit</h1>",
            (
                f'<p class="subtitle">{self._esc(report.hostname)} · '
                f"{self._esc(report.os_platform)} · scanned "
                f"{self._esc(report.scan_timestamp.isoformat())} · "
                f"{report.scan_duration_seconds:.2f}s</p>"
            ),
            self._hero(summary),
            self._coverage(report),
            self._actions(findings, summary.action_counts),
            "<h2>Your servers</h2>",
        ]
        for audit in report.audits:
            parts.append(self._server_card(audit))
        parts.extend(
            [
                '<details class="audit-log"><summary>Full audit log</summary>',
                self._summary(report),
                self._policy(report),
                self._config_health(report),
            ]
        )
        for audit in report.audits:
            parts.append(self._server(audit))
        parts.append(self._fleet(report))
        parts.append("<h2>Finding explanations</h2>")
        for view in finding_views(report):
            explanation = render_finding_text(view).rsplit("\nsee:", 1)[0]
            url = self._esc(finding_url(view.rule_id))
            parts.append(
                f'<pre class="finding-explanation">{self._marked(explanation)}</pre>'
                f'<p>see: <a href="{url}">{url}</a></p>'
            )
        parts.append(self._warnings(report))
        parts.append("</details>")
        parts.append(
            "<footer>Generated by mcp-audit. Env var values are never captured; "
            "only key names appear in any output.</footer>"
        )
        parts.append("</body></html>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _hero(self, summary: ReviewSummary) -> str:
        fixes = summary.action_counts["high"]
        if fixes:
            headline = f"{fixes} action{'s' if fixes != 1 else ''} need your review before use."
        elif summary.action_count:
            headline = "Review the reach and hygiene findings below."
        else:
            headline = "No findings recorded within the checks shown below."
        effort = (
            f"Estimated initial review: {summary.review_minutes} minutes; remediation time varies."
            if summary.action_count
            else "No fixes proposed; review coverage before relying on this result."
        )
        grade = summary.grade
        label = f"Grade {grade}" if grade else "Preview"
        cls = "grade" if grade else "grade preview"
        return (
            '<section class="hero" aria-label="Summary">'
            f'<div class="{cls}" aria-label="{label}">{grade or "Preview"}</div><div>'
            f"<h2>{self._esc(headline)}</h2><p>{self._esc(effort)}</p>"
            '<p class="caveat">Reach and hygiene, not a safety certificate.</p>'
            "</div></section>"
        )

    def _actions(self, findings: list[Action], counts: dict[str, int]) -> str:
        out: list[str] = []
        for severity, label in (("high", "Top fixes"), ("medium", "Worth a look"), ("low", "FYI")):
            entries = [action for action in findings if action.severity == severity]
            out.append(f"<section><h2>{label} · {counts[severity]}</h2>")
            if not entries:
                out.append('<p class="empty">No actions proposed in this category.</p>')
            for action in entries:
                steps = "".join(f"<li>{self._esc(step)}</li>" for step in action.steps)
                out.append(
                    '<article class="action">'
                    f"{self._sev_badge(severity)}<h3>{self._esc(action.title)}</h3>"
                    f'<ul>{steps}</ul><p class="muted">Found by: '
                    f"{self._esc('; '.join(action.sources))}</p></article>"
                )
            out.append("</section>")
        return "".join(out)

    def _server_card(self, audit: ServerAudit) -> str:
        srv = audit.server
        verbs = {
            PermissionCategory.FILE_READ: "reads files",
            PermissionCategory.FILE_WRITE: "writes files",
            PermissionCategory.NETWORK: "contacts the internet",
            PermissionCategory.SHELL_EXEC: "runs commands",
            PermissionCategory.DESTRUCTIVE: "can delete or overwrite data",
            PermissionCategory.EXFILTRATION: "can send data out",
        }
        categories = [f.category for f in audit.permissions] + [f.category for f in audit.capability_findings]
        capabilities = dict.fromkeys(verbs[category] for category in categories)
        reach = ", ".join(capabilities) or "No capabilities inferred; see coverage."
        keys = ", ".join(srv.env_keys) or "No env key names recorded"
        exposure = f"{audit.risk_score.composite:.1f}/10" if audit.risk_score else "not available"
        return (
            '<details class="server-card">'
            f"<summary>{self._esc(srv.name)} — {self._esc(audit.connection_status)}</summary>"
            f"<p>{self._esc(reach)}</p><p>{self._esc(srv.client.value)} · "
            f"<code>{self._esc(srv.config_path)}</code> · {self._esc(srv.transport.value)}</p>"
            f"<p>Env key names only: <code>{self._esc(keys)}</code></p>"
            f"<p>Capability exposure: {exposure}. Full findings and evidence are in the audit log.</p>"
            "</details>"
        )

    def _warnings(self, report: AuditReport) -> str:
        rows = [
            self._row(
                self._esc(w.code),
                self._esc(w.check or "—"),
                self._esc(", ".join(w.servers)),
                self._esc(w.message),
            )
            for w in report.warnings
        ]
        return self._table("Scan warnings", ["Code", "Check", "Servers", "Message"], rows)

    def _summary(self, report: AuditReport) -> str:
        connection_mode = {
            "attempted": "Connections attempted",
            "skipped": "Config only",
            "unknown": "Unknown",
        }[report.connection_mode.value]
        stats = [
            ("Connection mode", connection_mode),
            ("Discovered", report.servers_discovered),
            ("Connected", report.servers_connected),
            ("Failed", report.servers_failed),
            ("Tools", report.total_tools),
            ("High-risk servers", report.high_risk_servers),
        ]
        target_hunts = sum(bool(f.hunt_targets) for a in report.audits for f in a.injection_findings)
        if target_hunts:
            stats.append(("Fix now: metadata secret-target hunts", target_hunts))
        cells = "".join(
            f'<div class="stat"><div class="num">{value}</div>'
            f'<div class="label">{self._esc(label)}</div></div>'
            for label, value in stats
        )
        return f'<div class="summary">{cells}</div>'

    def _coverage(self, report: AuditReport) -> str:
        """Render recorded coverage without treating absent legacy data as success."""
        coverage = report.coverage
        if not coverage:
            return (
                '<section class="coverage-incomplete" aria-label="Coverage unknown">'
                "<strong>Coverage unknown:</strong> this report did not record which checks ran. "
                "Runtime security: UNKNOWN.</section>"
            )

        labels = {
            "config_health": "Config health",
            "permissions": "Permissions",
            "capabilities": "Capabilities",
            "metadata": "Metadata",
            "runtime_security": "Runtime security",
            "inject_check": "Hidden instructions",
            "ssrf_check": "Open-ended web requests",
            "egress_check": "Outbound destinations",
            "pin_check": "Changes since pinning",
            "trifecta_check": "Read, fetch and send combinations",
            "shadow_check": "Lookalike tool names",
            "escalation_check": "Capability changes",
            "provenance_check": "Launch configuration changes",
            "integrity_check": "Launch file changes",
            "verify_artifacts": "Registry package verification",
            "download_artifacts": "Downloaded artifact verification",
            "llm_analysis": "AI-assisted analysis",
        }
        complete = [
            labels.get(key, key.replace("_", " ").title())
            for key, value in coverage.items()
            if value.state == "complete"
        ]
        checked = "<strong>Checked:</strong> " + (
            ", ".join(self._esc(label) for label in complete) if complete else "None recorded."
        )
        strip = f'<div class="checked-strip" aria-label="Checked">{checked}</div>'

        incomplete = [(key, value) for key, value in coverage.items() if value.state != "complete"]
        details: list[str] = []
        needs_banner = False
        for key, value in incomplete:
            state = value.state
            reason = value.reason
            label = labels.get(key, key.replace("_", " ").title())
            if key == "runtime_security" and state in {"not_run", "not_requested"}:
                text = "Runtime security: NOT CHECKED"
                if reason:
                    text += f" ({reason})"
            elif key == "metadata" and state == "not_run" and reason == "connections disabled":
                text = "Metadata checks not run: connections disabled"
            else:
                text = f"{label}: {state.replace('_', ' ').upper()}"
                if reason:
                    text += f" — {reason}"
            details.append(f'<div class="coverage-item">{self._esc(text)}</div>')
            needs_banner = needs_banner or state in {"partial", "not_run"}

        rendered_details = "".join(details)
        if needs_banner:
            rendered_details = (
                '<section class="coverage-incomplete" aria-label="Incomplete coverage">'
                "<strong>Audit coverage is incomplete.</strong>" + rendered_details + "</section>"
            )

        missing = missing_checks(coverage)
        if missing:
            missing_text = "Coverage unknown: checks not recorded: " + ", ".join(missing)
            if "runtime_security" in missing:
                missing_text += ". Runtime security: UNKNOWN."
            unknown_banner = (
                '<section class="coverage-incomplete" aria-label="Coverage unknown">'
                f"{self._esc(missing_text)}</section>"
            )
        else:
            unknown_banner = ""
        return strip + rendered_details + unknown_banner

    def _server(self, audit: ServerAudit) -> str:
        srv = audit.server
        composite = audit.risk_score.composite if audit.risk_score else 0.0
        risk_badge = self._severity_badge_for_score(composite)
        head = (
            '<div class="server-head">'
            f"<h3>{self._esc(srv.name)}</h3>"
            f'<span class="badge muted">{self._esc(srv.source_label)}</span>'
            f'<span class="badge muted">{self._esc(srv.transport.value)}</span>'
            f'<span class="badge {self._status_class(audit.connection_status)}">'
            f"{self._esc(audit.connection_status)}</span>"
            f'<span class="badge {risk_badge}">capability exposure {composite:.1f}/10</span>'
            "</div>"
        )
        body = [
            head,
            f"<p>Source: {self._esc(srv.source_label)} | config_path: "
            f"<code>{self._esc(srv.config_path)}</code> | entry: {self._esc(srv.name)}</p>",
        ]
        if audit.canary is not None:
            summary = audit.canary
            body.append(
                f"<p>Canary: {self._esc(summary.status)}, "
                f"{summary.completed_calls}/{summary.call_budget} calls. "
                f"Not ruled out: {self._esc(', '.join(summary.not_excluded_descriptions))}.</p>"
            )
        if audit.connection_error:
            body.append(f'<p class="muted">Error: {self._esc(audit.connection_error)}</p>')

        body.append(self._permissions_table(audit))
        body.append(self._injection_table(audit))
        body.append(self._ssrf_table(audit))
        body.append(self._egress_table(audit))
        body.append(self._trifecta_table(audit))
        body.append(self._escalation_table(audit))
        body.append(self._provenance_table(audit))
        body.append(self._integrity_table(audit))
        body.append(self._package_verify_table(audit))
        body.append(self._artifact_verify_table(audit))
        body.append(self._drift_table(audit))
        return f'<div class="server">{"".join(body)}</div>'

    def _permissions_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity),
                self._esc(f.rule_id),
                self._esc(f.category.value),
                self._esc(f.tool_name),
                self._esc(f.confidence.value),
                self._esc("; ".join(f.evidence)),
            )
            for f in audit.permissions
        ]
        return self._table(
            "Permissions",
            ["Severity", "Rule", "Category", "Tool", "Confidence", "Evidence"],
            rows,
        )

    def _injection_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.pattern_name),
                self._esc(f.target_name or f.tool_name),
                self._esc(f.matched_text),
                self._esc(f.instruction_pattern or ""),
                self._esc(f.field_path or ""),
                self._esc(", ".join(f.hunt_targets)),
            )
            for f in audit.injection_findings
        ]
        return self._table(
            "Prompt-injection",
            [
                "Severity",
                "Rule",
                "Pattern",
                "Target",
                "Matched text",
                "Instruction pattern",
                "Field",
                "Secret targets",
            ],
            rows,
        )

    def _ssrf_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.pattern_name),
                self._esc(f.target_name),
                self._esc("; ".join(f.evidence)),
            )
            for f in audit.ssrf_findings
        ]
        return self._table("SSRF", ["Severity", "Rule", "Pattern", "Target", "Evidence"], rows)

    def _egress_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.kind.value),
                self._esc(f.target_name),
                self._esc(f.destination_host or "caller-controlled"),
                self._esc("; ".join(f.evidence)),
            )
            for f in audit.egress_findings
        ]
        return self._table("Egress", ["Severity", "Rule", "Kind", "Target", "Destination", "Evidence"], rows)

    def _trifecta_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(self._pairs(f.leg1_contributors)),
                self._esc(self._pairs(f.leg2_contributors)),
                self._esc(self._pairs(f.leg3_contributors)),
                self._esc(format_rule_of_two(f.rule_of_two) if f.rule_of_two else ""),
            )
            for f in audit.trifecta_findings
        ]
        return self._table(
            "Lethal trifecta",
            ["Severity", "Rule", "Leg 1 (read)", "Leg 2 (ingest)", "Leg 3 (exfil)", "Rule of Two"],
            rows,
        )

    def _escalation_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.kind.value),
                self._esc(f.tool_name),
                self._esc(
                    ", ".join(c.value for c in f.gained_categories)
                    or ", ".join(f.gained_patterns)
                    or ", ".join(f.annotation_changes)
                ),
            )
            for f in audit.escalation_findings
        ]
        return self._table(
            "Capability escalation (vs pin baseline)",
            ["Severity", "Rule", "Kind", "Tool", "Gained"],
            rows,
        )

    def _provenance_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.kind.value),
                self._esc(f.summary),
            )
            for f in audit.provenance_findings
        ]
        return self._table(
            "Provenance / launch-config drift (vs pin baseline)",
            ["Severity", "Rule", "Kind", "Change"],
            rows,
        )

    def _integrity_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.artifact_path),
                self._esc(f.summary),
            )
            for f in audit.integrity_findings
        ]
        return self._table(
            "Launch-artifact integrity (vs pin baseline)",
            ["Severity", "Rule", "Artifact", "Change"],
            rows,
        )

    def _package_verify_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f"{f.ecosystem}:{f.package}@{f.version}"),
                self._esc(f.summary),
            )
            for f in audit.package_verify_findings
        ]
        return self._table(
            "Registry package verification (vs pin baseline)",
            ["Severity", "Rule", "Package", "Change"],
            rows,
        )

    def _artifact_verify_table(self, audit: ServerAudit) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f"{f.ecosystem}:{f.package}@{f.version}"),
                self._esc(f.summary),
            )
            for f in audit.artifact_verify_findings
        ]
        return self._table(
            "Artifact byte verification (vs pin baseline)",
            ["Severity", "Rule", "Package", "Change"],
            rows,
        )

    def _drift_table(self, audit: ServerAudit) -> str:
        has_session = any(f.source == "session" for f in audit.drift_findings)
        rows = [
            self._row(
                self._esc(f.status.value),
                *([self._esc(f.severity)] if has_session else []),
                self._esc(f.tool_name),
                self._esc(f.summary),
                self._esc("; ".join(f.details)),
            )
            for f in audit.drift_findings
        ]
        headers = [
            "Status",
            *(["Severity"] if has_session else []),
            "Target" if has_session else "Tool",
            "Summary",
            "Details",
        ]
        return self._table("Surface drift" if has_session else "Schema drift", headers, rows)

    def _fleet(self, report: AuditReport) -> str:
        fleet_trifecta_rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(self._pairs(f.leg1_contributors)),
                self._esc(self._pairs(f.leg2_contributors)),
                self._esc(self._pairs(f.leg3_contributors)),
            )
            for f in report.fleet_trifecta_findings
        ]
        shadowing_rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.rule_id),
                self._esc(f.kind.value),
                self._esc(f.name),
                self._esc(self._pairs(f.collisions)),
            )
            for f in report.shadowing_findings
        ]
        out = ["<h2>Fleet-level findings</h2>"]
        out.append(
            self._table(
                "Fleet lethal trifecta (advisory)",
                ["Severity", "Rule", "Leg 1", "Leg 2", "Leg 3"],
                fleet_trifecta_rows,
                level=3,
            )
        )
        out.append(
            self._table(
                "Tool-name shadowing",
                ["Severity", "Rule", "Kind", "Name", "Colliding server/tool"],
                shadowing_rows,
                level=3,
            )
        )
        return "".join(out)

    def _config_health(self, report: AuditReport) -> str:
        rows = [
            self._row(
                self._sev_badge(f.severity.value),
                self._esc(f.finding_type),
                self._esc(f.server_name or "—"),
                self._esc(f.summary),
                self._esc(f.remediation),
            )
            for f in report.config_health_findings
        ]
        return self._table("Config health", ["Severity", "Type", "Server", "Summary", "Remediation"], rows)

    def _policy(self, report: AuditReport) -> str:
        result = report.policy_result
        if result is None:
            return ""
        status = (
            '<span class="policy-pass">PASSED</span>'
            if result.passed
            else '<span class="policy-fail">FAILED</span>'
        )
        rows = [
            self._row(
                self._sev_badge(v.severity),
                self._esc(v.rule),
                self._esc(v.server_name or "—"),
                self._esc(v.tool_name or "—"),
                self._esc(v.message),
            )
            for v in result.violations
        ]
        heading = f"<h2>Policy: {status}</h2>"
        if not rows:
            return f'{heading}<p class="empty">No violations.</p>'
        body = self._table_body(["Severity", "Rule", "Server", "Tool", "Message"], rows)
        return f"{heading}{body}"

    # ------------------------------------------------------------------
    # HTML helpers
    # ------------------------------------------------------------------

    def _table(self, title: str, headers: list[str], rows: list[str], level: int = 2) -> str:
        tag = f"h{level}"
        heading = f"<{tag}>{self._esc(title)}</{tag}>"
        if not rows:
            return (
                f'{heading}<p class="empty">No findings recorded. '
                "See coverage above for whether this check ran.</p>"
            )
        return heading + self._table_body(headers, rows)

    def _table_body(self, headers: list[str], rows: list[str]) -> str:
        head = "".join(f"<th>{self._esc(h)}</th>" for h in headers)
        return (
            '<div class="table-scroll" tabindex="0" role="region" aria-label="Audit table">'
            f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )

    def _row(self, *cells: str) -> str:
        # Cells are pre-escaped (or trusted badge/markup) by the caller.
        return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"

    def _sev_badge(self, severity: str) -> str:
        cls = _SEVERITY_CLASS.get(severity, "muted")
        label = {"high": "▲ Fix now", "medium": "◆ Worth a look", "low": "● FYI"}.get(severity, severity)
        return f'<span class="badge {cls}">{self._esc(label)}</span>'

    def _severity_badge_for_score(self, composite: float) -> str:
        if composite >= 7.0:
            return "sev-high"
        if composite >= 3.0:
            return "sev-medium"
        return "sev-low"

    def _status_class(self, status: str) -> str:
        return "ok" if status == "connected" else "muted"

    def _pairs(self, pairs: list[tuple[str, str]]) -> str:
        return "; ".join(f"{srv}/{tool}" for srv, tool in pairs)

    def _esc(self, value: str) -> str:
        return escape(render_invisibles(strip_controls(value)), quote=True)

    def _marked(self, value: str) -> str:
        """Escape untrusted text before highlighting the excerpt's match delimiters."""
        import re

        return re.sub(r"⟦([^⟦⟧]*)⟧", r"<mark>\1</mark>", self._esc(value))
