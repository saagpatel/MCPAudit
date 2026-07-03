"""MCP server — expose mcp-audit as an MCP server for Claude Desktop integration."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import anyio
import click
from rich.console import Console

from mcp_audit.discovery import discover_all_configs
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport
from mcp_audit.report import error_console as _error_console

logger = logging.getLogger(__name__)

_console = Console()

# Claude Desktop config paths
_CLAUDE_DESKTOP_CONFIG_PATHS = [
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".config" / "Claude" / "claude_desktop_config.json",  # Linux
]
# Claude Code config path
_CLAUDE_CODE_CONFIG_PATH = Path.home() / ".claude.json"

_MCP_AUDIT_SERVER_ENTRY: dict[str, Any] = {
    "command": "mcp-audit",
    "args": ["serve"],
}


def _install_to_config(config_path: Path, server_name: str = "mcp-audit") -> bool:
    """Add mcp-audit server entry to a JSON config file. Returns True on success."""
    if not config_path.exists():
        _console.print(f"[yellow]Config file not found: {config_path}[/yellow]")
        return False

    try:
        raw: Any = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        _error_console.print(f"[red]Could not read {config_path}: {exc}[/red]")
        return False

    if not isinstance(raw, dict):
        _error_console.print(f"[red]Unexpected config format in {config_path}[/red]")
        return False

    mcp_servers: dict[str, Any] = raw.setdefault("mcpServers", {})
    if server_name in mcp_servers:
        _console.print(f"[yellow]{server_name} already registered in {config_path}[/yellow]")
        return True

    mcp_servers[server_name] = _MCP_AUDIT_SERVER_ENTRY
    try:
        config_path.write_text(json.dumps(raw, indent=2))
        _console.print(f"[green]Registered {server_name} in {config_path}[/green]")
        return True
    except OSError as exc:
        _error_console.print(f"[red]Could not write {config_path}: {exc}[/red]")
        return False


async def _scan(options: ScanOptions) -> AuditReport:
    """Run the scan engine with the user's override file loaded.

    Deliberately passes no console: engine progress/warnings stay silent so
    nothing can leak onto stdout, which carries the MCP stdio protocol frames.
    """
    from mcp_audit.overrides import OverrideApplier, load_override_config

    applier = OverrideApplier(load_override_config())
    return await run_scan(options, override_applier=applier)


def _findings_payload(report: AuditReport, findings: list[dict[str, Any]]) -> str:
    """Wrap a findings list with the scan's coverage warnings.

    ``warnings`` is what lets a caller distinguish "checked, clean" (empty
    findings, empty warnings) from "check skipped" (empty findings plus a
    warning naming the missing baseline/credential and its remediation).
    """
    return json.dumps(
        {"findings": findings, "warnings": [w.model_dump() for w in report.warnings]},
        indent=2,
    )


def _build_mcp_server() -> Any:
    """Build and return the FastMCP server instance with all tools registered."""
    from mcp.server import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError

    app: Any = FastMCP(
        name="mcp-audit",
        instructions=(
            "Audit all locally configured MCP servers for permission risks, "
            "prompt injection threats, and schema drift."
        ),
    )

    @app.tool()  # type: ignore[untyped-decorator]
    async def scan_mcp_servers(skip_connect: bool = False) -> str:
        """Run a full audit of all discovered MCP servers. Returns JSON report."""
        report = await _scan(ScanOptions(skip_connect=skip_connect))
        return report.model_dump_json(indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_high_risk_servers() -> str:
        """Return servers with composite risk score ≥ 7.0. Returns JSON list."""
        report = await _scan(ScanOptions())
        high_risk = [
            {"name": a.server.name, "score": a.risk_score.composite if a.risk_score else 0.0}
            for a in report.audits
            if a.risk_score is not None and a.risk_score.composite >= 7.0
        ]
        return json.dumps(high_risk, indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def check_server(name: str) -> str:
        """Audit a single server by name. Returns JSON audit result."""
        report = await _scan(ScanOptions())
        audit = next((a for a in report.audits if a.server.name == name), None)
        if audit is None:
            # Raise so MCP clients see isError=true, not a successful call
            # whose payload smuggles an error they must parse out of band.
            raise ToolError(f"Server '{name}' not found")
        return audit.model_dump_json(indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_injection_findings() -> str:
        """Return all prompt injection findings across all servers. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(inject_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.injection_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "tool": f.tool_name,
                        "severity": f.severity,
                        "pattern": f.pattern_name,
                        "description": f.description,
                        "matched_text": f.matched_text,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_ssrf_findings() -> str:
        """Return all SSRF findings across all servers. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(ssrf_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.ssrf_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "target": f.target_name,
                        "target_type": f.target_type.value,
                        "severity": f.severity.value,
                        "pattern": f.pattern_name,
                        "description": f.description,
                        "evidence": f.evidence,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_trifecta_findings() -> str:
        """Return per-server and fleet-level lethal-trifecta findings. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(trifecta_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.trifecta_findings:
                all_findings.append(
                    {
                        "scope": "server",
                        "server": audit.server.name,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "leg1_contributors": f.leg1_contributors,
                        "leg2_contributors": f.leg2_contributors,
                        "leg3_contributors": f.leg3_contributors,
                        "description": f.description,
                    }
                )
        for f in report.fleet_trifecta_findings:
            all_findings.append(
                {
                    "scope": "fleet",
                    "server": "",
                    "severity": f.severity.value,
                    "rule_id": f.rule_id,
                    "leg1_contributors": f.leg1_contributors,
                    "leg2_contributors": f.leg2_contributors,
                    "leg3_contributors": f.leg3_contributors,
                    "description": f.description,
                }
            )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_shadowing_findings() -> str:
        """Return all cross-server tool-name shadowing findings. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(shadow_check=True))
        all_findings = []
        for f in report.shadowing_findings:
            all_findings.append(
                {
                    "kind": f.kind.value,
                    "severity": f.severity.value,
                    "rule_id": f.rule_id,
                    "canonical_name": f.name,
                    "collisions": f.collisions,
                    "description": f.description,
                }
            )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_escalation_findings() -> str:
        """Return capability-escalation findings vs the pin baseline. Returns JSON `{findings, warnings}`.

        Requires a pin baseline (run `mcp-audit pin` first); without pins `findings` is
        empty and `warnings` carries a `pin_baseline_missing` entry explaining why.
        """
        report = await _scan(ScanOptions(escalation_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.escalation_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "tool_name": f.tool_name,
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "gained_categories": [c.value for c in f.gained_categories],
                        "gained_patterns": f.gained_patterns,
                        "description": f.description,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_provenance_findings() -> str:
        """Return launch-config provenance drift vs the pin baseline. Returns JSON `{findings, warnings}`.

        Requires a pin baseline with a config snapshot (run `mcp-audit pin` first); without one
        `findings` is empty and `warnings` carries a `pin_baseline_missing` or
        `pin_baseline_stale` entry explaining why.
        """
        report = await _scan(ScanOptions(provenance_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.provenance_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "baseline": f.baseline,
                        "current": f.current,
                        "gained_flags": f.gained_flags,
                        "description": f.description,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_integrity_findings() -> str:
        """Return launch-artifact integrity drift vs the pin baseline. Returns JSON `{findings, warnings}`.

        Requires a pin baseline that captured artifact hashes (run `mcp-audit pin` first); without
        one `findings` is empty and `warnings` explains why. Offline — only on-disk bytes are hashed.
        """
        # Integrity is purely offline (re-hashing on-disk artifacts vs the pin
        # store), so skip spawning/connecting to servers entirely.
        report = await _scan(ScanOptions(skip_connect=True, integrity_check=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.integrity_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "artifact_path": f.artifact_path,
                        "baseline_hash": f.baseline_hash,
                        "current_hash": f.current_hash,
                        "description": f.description,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_package_verify_findings() -> str:
        """Return registry package-hash drift vs the pin baseline. Returns JSON `{findings, warnings}`.

        NETWORK: contacts the npm/PyPI registry. Requires a pin baseline captured with
        `mcp-audit pin --verify-artifacts`; without one `findings` is empty and `warnings`
        explains why. Does not connect to the audited MCP servers (skip_connect).
        """
        report = await _scan(ScanOptions(skip_connect=True, verify_artifacts=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.package_verify_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "ecosystem": f.ecosystem,
                        "package": f.package,
                        "version": f.version,
                        "baseline_hash": f.baseline_hash,
                        "current_hash": f.current_hash,
                        "description": f.description,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_artifact_verify_findings() -> str:
        """Return byte-level artifact drift vs the pin baseline. Returns JSON `{findings, warnings}`.

        NETWORK: downloads npm/PyPI artifact bytes and hashes them. Requires a pin baseline
        captured with `mcp-audit pin --download-artifacts`; without one `findings` is empty
        and `warnings` explains why. Does not connect to the audited MCP servers (skip_connect).
        """
        report = await _scan(ScanOptions(skip_connect=True, download_artifacts=True))
        all_findings = []
        for audit in report.audits:
            for f in audit.artifact_verify_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "kind": f.kind.value,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "ecosystem": f.ecosystem,
                        "package": f.package,
                        "version": f.version,
                        "baseline_hash": f.baseline_hash,
                        "current_hash": f.current_hash,
                        "description": f.description,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    def list_discovered_servers() -> str:
        """Return names and clients of all discovered MCP servers. Returns JSON list."""
        servers = discover_all_configs(None)
        return json.dumps(
            [{"name": s.name, "client": s.client.value, "transport": s.transport.value} for s in servers],
            indent=2,
        )

    return app


@click.command("serve")
@click.option(
    "--install",
    is_flag=True,
    default=False,
    help="Register mcp-audit in Claude Desktop/Code config.",
)
def serve_command(install: bool) -> None:
    """Expose mcp-audit as an MCP server for Claude Desktop / Claude Code integration."""
    if install:
        _do_install()
        return
    anyio.run(_serve)


def _do_install() -> None:
    """Write mcp-audit server entry to detected config files.

    Exit contract: 0 when no config exists (manual hint printed) or every
    found config was updated; 1 when any found config could not be updated —
    a found-but-unusable config must never masquerade as "not found".
    """
    found = 0
    succeeded = 0
    for config_path in [*_CLAUDE_DESKTOP_CONFIG_PATHS, _CLAUDE_CODE_CONFIG_PATH]:
        if not config_path.exists():
            continue
        found += 1
        if _install_to_config(config_path):
            succeeded += 1

    if found == 0:
        _console.print("[yellow]No Claude config files found. Add manually:[/yellow]")
        _console.print(
            '  Add to your claude_desktop_config.json or .claude.json under "mcpServers":\n'
            '  "mcp-audit": {"command": "mcp-audit", "args": ["serve"]}'
        )
        return
    if succeeded < found:
        # Per-file error text already printed by _install_to_config.
        raise SystemExit(1)


async def _serve() -> None:
    app = _build_mcp_server()
    import sys as _sys

    _sys.stderr.write("mcp-audit MCP server starting on stdio...\n")
    await app.run_stdio_async()
