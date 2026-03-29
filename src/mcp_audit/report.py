"""Report generators — Rich terminal table and JSON file output."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_audit.models import AuditReport, PermissionFinding, ServerAudit


def _default_console() -> Console:
    return Console()


class ReportGenerator:
    """Renders audit reports as Rich terminal output or JSON files."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or _default_console()

    def render_terminal(self, report: AuditReport, verbose: bool = False) -> None:
        """Print the full audit report to the console."""
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
        table.add_column("Risk", justify="right")
        table.add_column("Top Permissions", overflow="fold")
        table.add_column("Status", style="dim")

        for audit in report.audits:
            risk_text = self._risk_text(audit)
            perms = self._top_permissions(audit)
            status_str = audit.connection_status
            if audit.connection_error:
                status_str = f"{status_str}: {audit.connection_error[:40]}"

            table.add_row(
                audit.server.name,
                audit.server.client.value,
                str(len(audit.tools)),
                risk_text,
                perms,
                status_str,
            )

        self._console.print(table)

        if verbose:
            self._render_verbose(report)

    def _render_verbose(self, report: AuditReport) -> None:
        """Print per-tool permission breakdown for each server."""
        for audit in report.audits:
            if not audit.tools:
                continue
            self._console.print(f"\n[bold]{audit.server.name}[/bold] — tool details")
            sub = Table(show_lines=False, show_header=True)
            sub.add_column("Tool", style="cyan")
            sub.add_column("Permissions", overflow="fold")

            findings_by_tool: dict[str, list[PermissionFinding]] = {}
            for f in audit.permissions:
                findings_by_tool.setdefault(f.tool_name, []).append(f)

            for tool in audit.tools:
                tool_findings = findings_by_tool.get(tool.name, [])
                if tool_findings:
                    perm_str = ", ".join(
                        f"{f.category.value}({f.confidence.value})" for f in tool_findings
                    )
                else:
                    perm_str = "[dim]none[/dim]"
                sub.add_row(tool.name, perm_str)

            self._console.print(sub)

    def render_json(self, report: AuditReport, path: Path) -> None:
        """Write full AuditReport as JSON to the given path."""
        path.write_text(report.model_dump_json(indent=2))
        self._console.print(f"[green]JSON report written to {path}[/green]")

    def _risk_text(self, audit: ServerAudit) -> Text:
        if audit.risk_score is None:
            return Text("n/a", style="dim")
        score = audit.risk_score.composite
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
