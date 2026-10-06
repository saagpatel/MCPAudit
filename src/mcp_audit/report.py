"""Report generators — Rich terminal table and JSON file output."""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_audit.coverage import missing_checks
from mcp_audit.models import (
    ArtifactVerifySeverity,
    AuditReport,
    ConnectionMode,
    DriftStatus,
    EgressFinding,
    EgressSeverity,
    EscalationKind,
    EscalationSeverity,
    InjectionSeverity,
    IntegritySeverity,
    PackageVerifySeverity,
    PermissionFinding,
    ProvenanceSeverity,
    ServerAudit,
    ShadowingSeverity,
    SsrfSeverity,
    TrifectaSeverity,
)
from mcp_audit.taxonomy import format_rule_of_two
from mcp_audit.terminal_text import strip_controls, terminal_safe


def _default_console() -> Console:
    return Console()


# Shared stderr console for human-facing error text. Machine-parseable stdout
# (json/sarif pipelines) must never be polluted by error messages.
error_console = Console(stderr=True)


class ReportGenerator:
    """Renders audit reports as Rich terminal output or JSON files."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or _default_console()

    def render_terminal(self, report: AuditReport, verbose: bool = False) -> None:
        """Print the full audit report to the console."""
        report = report.redacted()
        n_clients = len({a.server.client for a in report.audits})
        server_label = "server" if report.servers_discovered == 1 else "servers"
        client_label = "client" if n_clients == 1 else "clients"
        risk_label = "high-risk server" if report.high_risk_servers == 1 else "high-risk servers"
        risk_style = "green bold" if report.high_risk_servers == 0 else "red bold"
        if report.connection_mode is ConnectionMode.SKIPPED:
            connection_summary = "[cyan]Config-only scan.[/cyan]"
        elif report.connection_mode is ConnectionMode.ATTEMPTED:
            connection_summary = f"[yellow]{report.servers_failed} failed to connect.[/yellow]"
        else:
            connection_summary = "[yellow]Connection mode unknown.[/yellow]"

        summary = (
            f"Scanned [bold]{report.servers_discovered}[/bold] {server_label} across "
            f"[bold]{n_clients}[/bold] {client_label}. "
            f"[{risk_style}]{report.high_risk_servers} {risk_label}.[/{risk_style}] "
            f"{connection_summary} "
            f"({report.scan_duration_seconds:.1f}s)"
        )
        self._console.print(Panel(summary, title="mcp-audit scan", expand=False))

        secret_hunts = sum(bool(f.secret_targets) for a in report.audits for f in a.injection_findings)
        if secret_hunts:
            self._console.print(f"[bold red]Fix now:[/bold red] {secret_hunts} metadata secret-target hunts.")

        self._render_coverage(report)

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

        visible_audits = report.audits[:200]
        for audit in visible_audits:
            risk_text = self._risk_text(audit)
            non_tool_risk_text = self._non_tool_risk_text(audit)
            perms = self._top_permissions(audit)
            status_str = audit.connection_status
            if audit.connection_error:
                status_str = f"{status_str}: {audit.connection_error[:40]}"

            table.add_row(
                terminal_safe(audit.server.name),
                terminal_safe(audit.server.client.value),
                terminal_safe(str(len(audit.tools))),
                terminal_safe(str(len(audit.prompts))),
                terminal_safe(str(len(audit.resources))),
                risk_text,
                non_tool_risk_text,
                perms,
                terminal_safe(status_str),
            )

        self._console.print(table)
        remaining = len(report.audits) - len(visible_audits)
        if remaining:
            self._console.print(f"[dim](+{remaining} more; see --json)[/dim]")

        for audit in report.audits:
            if audit.canary is not None:
                canary = audit.canary
                self._console.print(
                    terminal_safe(
                        f"Canary {audit.server.name}: {canary.status}, "
                        f"{canary.completed_calls}/{canary.call_budget} calls"
                    )
                )
                self._console.print(
                    terminal_safe("Not ruled out: " + ", ".join(canary.not_excluded_descriptions) + ".")
                )

        if verbose:
            self._render_verbose(report)

        self._render_injection_warnings(report)
        self._render_ssrf_warnings(report)
        self._render_egress_warnings(report)
        self._render_trifecta_warnings(report)
        self._render_shadowing_warnings(report)
        self._render_escalation_warnings(report)
        self._render_provenance_warnings(report)
        self._render_integrity_warnings(report)
        self._render_package_verify_warnings(report)
        self._render_artifact_verify_warnings(report)
        self._render_capability_warnings(report)
        self._render_drift_warnings(report)
        self._render_policy_result(report)

    def _render_coverage(self, report: AuditReport) -> None:
        """Show which checks ran, including checks omitted by older reports."""
        coverage = report.coverage
        if not coverage:
            self._console.print("[yellow]Coverage unknown: checks were not recorded.[/yellow]")
            self._console.print("[yellow]Runtime security: UNKNOWN (coverage not recorded)[/yellow]")
            return

        labels = {
            "config_health": "Config health",
            "permissions": "Permissions",
            "capabilities": "Capabilities",
            "metadata": "Metadata",
            "runtime_security": "Runtime security",
        }
        completed = [
            labels.get(key, key.replace("_", " ").title())
            for key, value in coverage.items()
            if value.state == "complete"
        ]
        if completed:
            self._console.print(terminal_safe("Checked: " + ", ".join(completed)))

        incomplete = [
            (key, value)
            for key, value in coverage.items()
            if value.state in {"partial", "not_run"}
            or (key == "runtime_security" and value.state == "not_requested")
        ]
        for key, value in incomplete:
            label = labels.get(key, key.replace("_", " ").title())
            state = value.state
            reason = value.reason
            if key == "runtime_security" and state in {"not_run", "not_requested"}:
                message = "Runtime security: NOT CHECKED"
                if reason:
                    message += f" ({reason})"
            elif key == "metadata" and state == "not_run" and reason == "connections disabled":
                message = "Metadata checks not run: connections disabled"
            else:
                message = f"{label}: {state.replace('_', ' ').upper()}"
                if reason:
                    message += f" — {reason}"
            self._console.print(terminal_safe(message))

        if any(value.state in {"partial", "not_run"} for _, value in incomplete):
            self._console.print("[yellow]Audit coverage is incomplete.[/yellow]")

        missing = missing_checks(coverage)
        if missing:
            self._console.print(terminal_safe("Coverage unknown: checks not recorded: " + ", ".join(missing)))
            if "runtime_security" in missing:
                self._console.print("[yellow]Runtime security: UNKNOWN (coverage not recorded)[/yellow]")

    def _render_verbose(self, report: AuditReport) -> None:
        """Print per-tool permission breakdown for each server."""
        for audit in report.audits:
            if not audit.tools:
                continue
            self._console.print(
                Text.assemble("\n", (strip_controls(audit.server.name), "bold"), " — tool details")
            )
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
                    perm_str = terminal_safe(
                        ", ".join(
                            f"{f.rule_id} {f.category.value}({f.confidence.value})" for f in tool_findings
                        )
                    )
                    action_str = terminal_safe(" ".join(f.remediation for f in tool_findings))
                else:
                    perm_str = Text("none", style="dim")
                    action_str = Text("none", style="dim")
                sub.add_row(terminal_safe(tool.name), perm_str, action_str)

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
                terminal_safe(server_name),
                terminal_safe(f.target_type.value),
                terminal_safe(f.target_name or f.tool_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.pattern_name),
                terminal_safe(f.description),
                terminal_safe(f.remediation),
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
                terminal_safe(server_name),
                terminal_safe(f.target_type.value),
                terminal_safe(f.target_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.pattern_name),
                terminal_safe("; ".join(f.evidence)),
                terminal_safe(f.remediation),
            )
        self._console.print(tbl)

    def _render_egress_warnings(self, report: AuditReport) -> None:
        """Print egress (outbound-destination) findings section if any were found."""
        all_findings = [(a.server.name, f) for a in report.audits for f in a.egress_findings]
        if not all_findings:
            return

        self._console.print()
        self._console.rule("[bold red]Egress / Outbound Destinations[/bold red]")
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Severity", no_wrap=True)
        tbl.add_column("Rule", no_wrap=True)
        tbl.add_column("Destination", no_wrap=True)
        tbl.add_column("Evidence", overflow="fold")

        for server_name, f in all_findings:
            sev_style = {
                EgressSeverity.HIGH: "bold red",
                EgressSeverity.MEDIUM: "yellow",
                EgressSeverity.LOW: "dim",
            }.get(f.severity, "")
            tbl.add_row(
                terminal_safe(server_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.rule_id),
                self._egress_destination_label(f),
                terminal_safe(f"{f.kind.value}: {'; '.join(f.evidence)}"),
            )
        self._console.print(tbl)

    @staticmethod
    def _egress_destination_label(finding: EgressFinding) -> Text:
        destination_host = finding.destination_host
        if destination_host:
            return terminal_safe(f"{destination_host} ({finding.target_name})")
        return Text("caller-controlled", style="dim")

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
            tbl.add_column("Leg 2 (untrusted ingestion)", overflow="fold")
            tbl.add_column("Leg 3 (exfiltration)", overflow="fold")
            tbl.add_column("Rule of Two", overflow="fold")
            for server_name, f in per_server:
                tbl.add_row(
                    terminal_safe(server_name),
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg1_contributors)),
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg2_contributors)),
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg3_contributors)),
                    terminal_safe(format_rule_of_two(f.rule_of_two) if f.rule_of_two else f.remediation),
                )
            self._console.print(tbl)

        if fleet:
            tbl2 = Table(show_lines=True, title="Fleet-Level Trifecta (MEDIUM — advisory)")
            tbl2.add_column("Leg 1 (file_read)", overflow="fold")
            tbl2.add_column("Leg 2 (untrusted ingestion)", overflow="fold")
            tbl2.add_column("Leg 3 (exfiltration)", overflow="fold")
            tbl2.add_column("Rule of Two", overflow="fold")
            for f in fleet:
                sev_style = "bold red" if f.severity == TrifectaSeverity.HIGH else "yellow"
                posture = format_rule_of_two(f.rule_of_two) if f.rule_of_two else f.remediation
                tbl2.add_row(
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg1_contributors)),
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg2_contributors)),
                    terminal_safe("; ".join(f"{s}/{t}" for s, t in f.leg3_contributors)),
                    Text(strip_controls(posture), style=sev_style),
                )
            self._console.print(tbl2)

    def _render_shadowing_warnings(self, report: AuditReport) -> None:
        """Print cross-server tool-name shadowing findings if any were found."""
        findings = list(report.shadowing_findings)
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Tool-Name Shadowing[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Kind", style="cyan")
        tbl.add_column("Severity")
        tbl.add_column("Canonical Name", style="bold")
        tbl.add_column("Colliding Servers / Tools", overflow="fold")
        tbl.add_column("Suggested Action", overflow="fold")

        for f in findings:
            sev_style = {
                ShadowingSeverity.HIGH: "bold red",
                ShadowingSeverity.MEDIUM: "yellow",
                ShadowingSeverity.LOW: "dim",
            }.get(f.severity, "")
            pairs = "; ".join(f"{srv}/{tool}" for srv, tool in f.collisions)
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(f.kind.value),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.name),
                terminal_safe(pairs),
                terminal_safe(f.remediation),
            )
        self._console.print(tbl)

    def _render_escalation_warnings(self, report: AuditReport) -> None:
        """Print capability-escalation (rug-pull) findings vs the pin baseline if any were found."""
        findings = [(a.server.name, f) for a in report.audits for f in a.escalation_findings]
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Capability Escalation (vs pin baseline)[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Tool", style="cyan")
        tbl.add_column("Kind")
        tbl.add_column("Severity")
        tbl.add_column("Gained", overflow="fold", min_width=18)
        tbl.add_column("Suggested Action", overflow="fold", max_width=42)

        for server_name, f in findings:
            sev_style = {
                EscalationSeverity.HIGH: "bold red",
                EscalationSeverity.MEDIUM: "yellow",
            }.get(f.severity, "")
            gained = (
                ", ".join(c.value for c in f.gained_categories)
                if f.kind == EscalationKind.CAPABILITY
                else ", ".join(f.annotation_changes)
                if f.kind == EscalationKind.ANNOTATION_DELTA
                else ", ".join(f.gained_patterns)
            )
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(server_name),
                terminal_safe(f.tool_name),
                terminal_safe(f.kind.value),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(gained),
                terminal_safe(f.remediation),
            )
        self._console.print(tbl)

    def _render_provenance_warnings(self, report: AuditReport) -> None:
        """Print launch-config / provenance drift findings vs the pin baseline if any."""
        findings = [(a.server.name, f) for a in report.audits for f in a.provenance_findings]
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Provenance / Launch-Config Drift (vs pin baseline)[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Kind")
        tbl.add_column("Severity")
        tbl.add_column("Change", overflow="fold")

        for server_name, f in findings:
            sev_style = {
                ProvenanceSeverity.HIGH: "bold red",
                ProvenanceSeverity.MEDIUM: "yellow",
            }.get(f.severity, "")
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(server_name),
                terminal_safe(f.kind.value),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.summary),
            )
        self._console.print(tbl)

    def _render_integrity_warnings(self, report: AuditReport) -> None:
        """Print launch-artifact integrity (on-disk hash) drift vs the pin baseline if any."""
        findings = [(a.server.name, f) for a in report.audits for f in a.integrity_findings]
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Launch-Artifact Integrity (vs pin baseline)[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Severity")
        tbl.add_column("Artifact", overflow="fold")
        tbl.add_column("Change", overflow="fold")

        for server_name, f in findings:
            sev_style = {
                IntegritySeverity.HIGH: "bold red",
                IntegritySeverity.MEDIUM: "yellow",
            }.get(f.severity, "")
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(server_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f.artifact_path),
                terminal_safe(f.summary),
            )
        self._console.print(tbl)

    def _render_package_verify_warnings(self, report: AuditReport) -> None:
        """Print registry package-verification drift vs the pin baseline if any."""
        findings = [(a.server.name, f) for a in report.audits for f in a.package_verify_findings]
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Registry Package Verification (vs pin baseline)[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Severity")
        tbl.add_column("Package", overflow="fold")
        tbl.add_column("Change", overflow="fold")

        for server_name, f in findings:
            sev_style = {
                PackageVerifySeverity.HIGH: "bold red",
                PackageVerifySeverity.MEDIUM: "yellow",
            }.get(f.severity, "")
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(server_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f"{f.ecosystem}:{f.package}@{f.version}"),
                terminal_safe(f.summary),
            )
        self._console.print(tbl)

    def _render_artifact_verify_warnings(self, report: AuditReport) -> None:
        """Print byte-level artifact-verification findings vs the pin baseline if any."""
        findings = [(a.server.name, f) for a in report.audits for f in a.artifact_verify_findings]
        if not findings:
            return

        self._console.print()
        self._console.rule("[bold red]Artifact Byte Verification (vs pin baseline)[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Rule ID", style="bold red", no_wrap=True)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Severity")
        tbl.add_column("Package", overflow="fold")
        tbl.add_column("Change", overflow="fold")

        for server_name, f in findings:
            sev_style = {
                ArtifactVerifySeverity.HIGH: "bold red",
                ArtifactVerifySeverity.MEDIUM: "yellow",
            }.get(f.severity, "")
            tbl.add_row(
                terminal_safe(f.rule_id),
                terminal_safe(server_name),
                Text(strip_controls(f.severity.value), style=sev_style),
                terminal_safe(f"{f.ecosystem}:{f.package}@{f.version}"),
                terminal_safe(f.summary),
            )
        self._console.print(tbl)

    def _render_drift_warnings(self, report: AuditReport) -> None:
        """Print tool schema drift warnings if any were found."""
        all_drifts = [(a.server.name, d) for a in report.audits for d in a.drift_findings]
        if not all_drifts:
            return

        self._console.print()
        has_session = any(d.source == "session" for _, d in all_drifts)
        title = "MCP Surface Drift" if has_session else "Tool Schema Drift"
        self._console.rule(Text(strip_controls(f"{title}"), style="bold yellow"))
        tbl = Table(show_lines=False)
        tbl.add_column("Server", style="bold cyan", no_wrap=True)
        tbl.add_column("Target" if has_session else "Tool", style="cyan")
        tbl.add_column("Status")
        if has_session:
            tbl.add_column("Severity")
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
            meaning = (
                "; ".join(filter(None, [d.summary, details]))
                if d.source == "session"
                else d.summary or details
            )
            tbl.add_row(
                terminal_safe(server_name),
                terminal_safe(d.tool_name),
                Text(strip_controls(d.status.value), style=status_style),
                *([terminal_safe(d.severity)] if has_session else []),
                terminal_safe(meaning),
                terminal_safe(d.remediation),
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
                terminal_safe(server_name),
                terminal_safe(finding.target_type.value),
                terminal_safe(finding.target_name),
                terminal_safe(finding.category.value),
                terminal_safe(finding.severity),
                terminal_safe(finding.remediation),
            )
        self._console.print(tbl)

    def render_json(self, report: AuditReport, path: Path) -> None:
        """Write full AuditReport as JSON to the given path."""
        redacted = report.redacted().model_dump(mode="json")
        path.write_text(json.dumps(redacted, indent=2))
        self._console.print(terminal_safe(f"JSON report written to {path}"), style="green")

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
                terminal_safe(violation.rule),
                terminal_safe(violation.server_name or "n/a"),
                terminal_safe(violation.tool_name or "n/a"),
                terminal_safe(violation.severity),
                terminal_safe(violation.message),
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

    def _top_permissions(self, audit: ServerAudit) -> Text:
        if not audit.permissions:
            return Text("none", style="dim")
        # Deduplicate by category, pick highest confidence
        best: dict[str, str] = {}
        for f in audit.permissions:
            cat = f.category.value
            conf = f.confidence.value
            if cat not in best:
                best[cat] = conf
        return terminal_safe(", ".join(f"{cat}({conf})" for cat, conf in best.items()))

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


def scrub_report_identifiers(report: AuditReport) -> AuditReport:
    """Compatibility wrapper for the field-report redaction entry point."""
    return report.redacted(identifiers=True)
