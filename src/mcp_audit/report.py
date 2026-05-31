"""Report generators — Rich terminal table and JSON file output."""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_audit.models import (
    AuditReport,
    DriftStatus,
    InjectionSeverity,
    PermissionFinding,
    ServerAudit,
    SsrfSeverity,
    TrifectaSeverity,
)
from mcp_audit.redaction import redact_data, redact_text


def _default_console() -> Console:
    return Console()


class ReportGenerator:
    """Renders audit reports as Rich terminal output or JSON files."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or _default_console()

    def render_terminal(self, report: AuditReport, verbose: bool = False) -> None:
        """Print the full audit report to the console."""
        report = _redacted_report(report)
        n_clients = len({a.server.client for a in report.audits})

        summary = (
            f"Scanned [bold]{report.servers_discovered}[/bold] servers across "
            f"[bold]{n_clients}[/bold] clients. "
            f"[red bold]{report.high_risk_servers} high-risk.[/red bold] "
            f"[yellow]{report.servers_failed} failed to connect.[/yellow] "
            f"({report.scan_duration_seconds:.1f}s)"
        )
        self._console.print(Panel(summary, title="mcp-audit scan", expand=False))

        if not report.audits:
            self._console.print("[dim]No servers found.[/dim]")
            return

        table = Table(title=None, show_lines=True)
        table.add_column("Server", style="bold cyan", no_wrap=True)
        table.add_column("Client", style="magenta")
        table.add_column("Tools", justify="right")
        table.add_column("Prompts", justify="right")
        table.add_column("Resources", justify="right")
        table.add_column("Risk", justify="right")
        table.add_column("Non-Tool", justify="right")
        table.add_column("Top Permissions", overflow="fold")
        table.add_column("Status", style="dim")

        for audit in report.audits:
            risk_text = self._risk_text(audit)
            non_tool_risk_text = self._non_tool_risk_text(audit)
            perms = self._top_permissions(audit)
            status_str = audit.connection_status
            if audit.connection_error:
                status_str = f"{status_str}: {redact_text(audit.connection_error)[:40]}"

            table.add_row(
                audit.server.name,
                audit.server.client.value,
                str(len(audit.tools)),
                str(len(audit.prompts)),
                str(len(audit.resources)),
                risk_text,
                non_tool_risk_text,
                perms,
                status_str,
            )

        self._console.print(table)

        if verbose:
            self._render_verbose(report)

        self._render_injection_warnings(report)
        self._render_ssrf_warnings(report)
        self._render_trifecta_warnings(report)
        self._render_capability_warnings(report)
        self._render_drift_warnings(report)
        self._render_policy_result(report)

    def _render_verbose(self, report: AuditReport) -> None:
        """Print per-tool permission breakdown for each server."""
        for audit in report.audits:
            if not audit.tools:
                continue
            self._console.print(f"\n[bold]{audit.server.name}[/bold] — tool details")
            sub = Table(show_lines=False, show_header=True)
            sub.add_column("Tool", style="cyan")
            sub.add_column("Permissions", overflow="fold")
            sub.add_column("Suggested Action", overflow="fold")

            findings_by_tool: dict[str, list[PermissionFinding]] = {}
            for f in audit.permissions:
                findings_by_tool.setdefault(f.tool_name, []).append(f)

            for tool in audit.tools:
                tool_findings = findings_by_tool.get(tool.name, [])
                if tool_findings:
                    perm_str = ", ".join(
                        f"{f.rule_id} {f.category.value}({f.confidence.value})" for f in tool_findings
                    )
                    action_str = " ".join(f.remediation for f in tool_findings)
                else:
                    perm_str = "[dim]none[/dim]"
                    action_str = "[dim]none[/dim]"
                sub.add_row(tool.name, perm_str, action_str)

            self._console.print(sub)

    def _render_injection_warnings(self, report: AuditReport) -> None:
        """Print injection findings section if any were found."""
        all_findings = [(a.server.name, f) for a in report.audits for f in a.injection_findings]
        if not all_findings:
            return

        self._console.print()
        self._console.rule("[bold red]Prompt Injection Warnings[/bold red]")
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Type", style="cyan")
        tbl.add_column("Target", style="cyan")
        tbl.add_column("Severity")
        tbl.add_column("Pattern")
        tbl.add_column("Description", overflow="fold")
        tbl.add_column("Suggested Action", overflow="fold")

        for server_name, f in all_findings:
            sev_style = {
                InjectionSeverity.HIGH: "bold red",
                InjectionSeverity.MEDIUM: "yellow",
                InjectionSeverity.LOW: "dim",
            }.get(f.severity, "")
            tbl.add_row(
                server_name,
                f.target_type.value,
                f.target_name or f.tool_name,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.pattern_name,
                f.description,
                f.remediation,
            )
        self._console.print(tbl)

    def _render_ssrf_warnings(self, report: AuditReport) -> None:
        """Print SSRF findings section if any were found."""
        all_findings = [(a.server.name, f) for a in report.audits for f in a.ssrf_findings]
        if not all_findings:
            return

        self._console.print()
        self._console.rule("[bold red]SSRF Warnings[/bold red]")
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Type", style="cyan")
        tbl.add_column("Target", style="cyan")
        tbl.add_column("Severity")
        tbl.add_column("Pattern")
        tbl.add_column("Evidence", overflow="fold")
        tbl.add_column("Suggested Action", overflow="fold")

        for server_name, f in all_findings:
            sev_style = {
                SsrfSeverity.HIGH: "bold red",
                SsrfSeverity.MEDIUM: "yellow",
                SsrfSeverity.LOW: "dim",
            }.get(f.severity, "")
            tbl.add_row(
                server_name,
                f.target_type.value,
                f.target_name,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.pattern_name,
                "; ".join(f.evidence),
                f.remediation,
            )
        self._console.print(tbl)

    def _render_trifecta_warnings(self, report: AuditReport) -> None:
        """Print lethal-trifecta findings (per-server and fleet-level) if any were found."""
        per_server = [(a.server.name, f) for a in report.audits for f in a.trifecta_findings]
        fleet = list(report.fleet_trifecta_findings)
        if not per_server and not fleet:
            return

        self._console.print()
        self._console.rule("[bold red]Lethal Trifecta / Toxic Flow[/bold red]")

        if per_server:
            tbl = Table(show_lines=True, title="Per-Server Trifecta (HIGH)")
            tbl.add_column("Server", style="bold cyan", no_wrap=True)
            tbl.add_column("Leg 1 (file_read)", overflow="fold")
            tbl.add_column("Leg 2 (network)", overflow="fold")
            tbl.add_column("Leg 3 (exfil/shell/write)", overflow="fold")
            tbl.add_column("Suggested Action", overflow="fold")
            for server_name, f in per_server:
                tbl.add_row(
                    server_name,
                    "; ".join(f"{s}/{t}" for s, t in f.leg1_contributors),
                    "; ".join(f"{s}/{t}" for s, t in f.leg2_contributors),
                    "; ".join(f"{s}/{t}" for s, t in f.leg3_contributors),
                    f.remediation,
                )
            self._console.print(tbl)

        if fleet:
            tbl2 = Table(show_lines=True, title="Fleet-Level Trifecta (MEDIUM — advisory)")
            tbl2.add_column("Leg 1 (file_read)", overflow="fold")
            tbl2.add_column("Leg 2 (network)", overflow="fold")
            tbl2.add_column("Leg 3 (exfil/shell/write)", overflow="fold")
            tbl2.add_column("Suggested Action", overflow="fold")
            for f in fleet:
                sev_style = "bold red" if f.severity == TrifectaSeverity.HIGH else "yellow"
                tbl2.add_row(
                    "; ".join(f"{s}/{t}" for s, t in f.leg1_contributors),
                    "; ".join(f"{s}/{t}" for s, t in f.leg2_contributors),
                    "; ".join(f"{s}/{t}" for s, t in f.leg3_contributors),
                    f"[{sev_style}]{f.remediation}[/{sev_style}]",
                )
            self._console.print(tbl2)

    def _render_drift_warnings(self, report: AuditReport) -> None:
        """Print tool schema drift warnings if any were found."""
        all_drifts = [(a.server.name, d) for a in report.audits for d in a.drift_findings]
        if not all_drifts:
            return

        self._console.print()
        self._console.rule("[bold yellow]Tool Schema Drift[/bold yellow]")
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Tool", style="cyan")
        tbl.add_column("Status")
        tbl.add_column("Meaning", overflow="fold")
        tbl.add_column("Suggested Action", overflow="fold")

        for server_name, d in all_drifts:
            status_style = {
                DriftStatus.CHANGED: "yellow",
                DriftStatus.NEW: "green",
                DriftStatus.REMOVED: "red",
            }.get(d.status, "")
            details = ""
            if d.status == DriftStatus.CHANGED:
                stored = d.stored_hash[:16] if d.stored_hash else "?"
                current = d.current_hash[:16] if d.current_hash else "?"
                details = f"{stored}… → {current}…"
                if d.details:
                    details = f"{details}; {', '.join(d.details)}"
            elif d.status == DriftStatus.NEW:
                details = ", ".join(d.details) or "not previously pinned"
            elif d.status == DriftStatus.REMOVED:
                details = ", ".join(d.details) or "tool no longer present"
            meaning = d.summary or details
            tbl.add_row(
                server_name,
                d.tool_name,
                f"[{status_style}]{d.status.value}[/{status_style}]",
                meaning,
                d.remediation,
            )
        self._console.print(tbl)

    def _render_capability_warnings(self, report: AuditReport) -> None:
        """Print non-tool capability findings if any were found."""
        all_findings = [(a.server.name, f) for a in report.audits for f in a.capability_findings]
        if not all_findings:
            return

        self._console.print()
        self._console.rule("[bold yellow]Prompt And Resource Capability Findings[/bold yellow]")
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Type", style="cyan")
        tbl.add_column("Name", overflow="fold")
        tbl.add_column("Permission")
        tbl.add_column("Severity")
        tbl.add_column("Suggested Action", overflow="fold")

        for server_name, finding in all_findings:
            tbl.add_row(
                server_name,
                finding.target_type.value,
                finding.target_name,
                finding.category.value,
                finding.severity,
                finding.remediation,
            )
        self._console.print(tbl)

    def render_json(self, report: AuditReport, path: Path) -> None:
        """Write full AuditReport as JSON to the given path."""
        redacted = redact_data(report.model_dump(mode="json"))
        path.write_text(json.dumps(redacted, indent=2))
        self._console.print(f"[green]JSON report written to {path}[/green]")

    def _render_policy_result(self, report: AuditReport) -> None:
        """Print local policy gate result if a policy was evaluated."""
        result = report.policy_result
        if result is None:
            return

        self._console.print()
        if result.passed:
            self._console.print("[green]Policy Gate: passed[/green]")
            return

        self._console.rule("[bold red]Policy Gate Failed[/bold red]")
        tbl = Table(show_lines=False)
        tbl.add_column("Rule", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="cyan")
        tbl.add_column("Tool", style="cyan")
        tbl.add_column("Severity")
        tbl.add_column("Message", overflow="fold")
        for violation in result.violations:
            tbl.add_row(
                violation.rule,
                violation.server_name or "n/a",
                violation.tool_name or "n/a",
                violation.severity,
                violation.message,
            )
        self._console.print(tbl)

    def _risk_text(self, audit: ServerAudit) -> Text:
        if audit.risk_score is None:
            return Text("n/a", style="dim")
        score = audit.risk_score.composite
        label = f"{score:.1f}"
        style = self._risk_style(score)
        return Text(label, style=style)

    def _non_tool_risk_text(self, audit: ServerAudit) -> Text:
        if audit.non_tool_risk is None:
            return Text("n/a", style="dim")
        score = audit.non_tool_risk.composite
        label = f"{score:.1f}"
        style = self._risk_style(score)
        return Text(label, style=style)

    def _risk_style(self, score: float) -> str:
        if score >= 7.0:
            return "bold red"
        if score >= 3.0:
            return "yellow"
        return "green"

    def _top_permissions(self, audit: ServerAudit) -> str:
        if not audit.permissions:
            return "[dim]none[/dim]"
        # Deduplicate by category, pick highest confidence
        best: dict[str, str] = {}
        for f in audit.permissions:
            cat = f.category.value
            conf = f.confidence.value
            if cat not in best:
                best[cat] = conf
        return ", ".join(f"{cat}({conf})" for cat, conf in best.items())

    def capture_terminal(self, report: AuditReport, verbose: bool = False) -> str:
        """Render to string (useful for testing)."""
        buf = io.StringIO()
        cap_console = Console(file=buf, force_terminal=True, width=120, highlight=False)
        orig = self._console
        self._console = cap_console
        try:
            self.render_terminal(report, verbose=verbose)
        finally:
            self._console = orig
        return buf.getvalue()


def _redacted_report(report: AuditReport) -> AuditReport:
    data = redact_data(report.model_dump(mode="json"))
    return AuditReport.model_validate(data)
