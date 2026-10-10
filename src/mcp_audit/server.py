"""MCP server — expose mcp-audit as an MCP server for Claude Desktop integration."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import anyio
import click
from rich.console import Console

from mcp_audit.discovery import ConfigParseError, discover_all_configs
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, ServerConfig
from mcp_audit.report import error_console as _error_console
from mcp_audit.terminal_text import TerminalSafeLogFilter, terminal_safe

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())

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
        _console.print(terminal_safe(f"Config file not found: {config_path}"), style="yellow")
        return False

    try:
        target_path = config_path.resolve(strict=True)
        raw: Any = json.loads(target_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        _error_console.print(terminal_safe(f"Could not read {config_path}: {exc}"), style="red")
        return False

    if not isinstance(raw, dict):
        _error_console.print(terminal_safe(f"Unexpected config format in {config_path}"), style="red")
        return False

    mcp_servers: dict[str, Any] = raw.setdefault("mcpServers", {})
    if server_name in mcp_servers:
        _console.print(terminal_safe(f"{server_name} already registered in {config_path}"), style="yellow")
        return True

    mcp_servers[server_name] = _MCP_AUDIT_SERVER_ENTRY
    temporary_path: Path | None = None
    try:
        mode = target_path.stat().st_mode & 0o777
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target_path.name}.", dir=target_path.parent)
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(raw, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.chmod(mode)
        os.replace(temporary_path, target_path)
        _console.print(terminal_safe(f"Registered {server_name} in {config_path}"), style="green")
        return True
    except OSError as exc:
        _error_console.print(terminal_safe(f"Could not write {config_path}: {exc}"), style="red")
        return False
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


async def _scan(options: ScanOptions, *, servers: list[ServerConfig] | None = None) -> AuditReport:
    """Run the scan engine with the user's override file loaded.

    Forward an explicit server list unchanged so the engine skips discovery.
    Deliberately passes no console: engine progress/warnings stay silent so
    nothing can leak onto stdout, which carries the MCP stdio protocol frames.
    """
    from mcp_audit.overrides import OverrideApplier, load_override_config

    applier = OverrideApplier(load_override_config())
    return await run_scan(options, servers=servers, override_applier=applier)


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
    """Build and return the MCPServer instance with all tools registered."""
    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError

    app: Any = MCPServer(
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
        report = report.redacted()
        return report.model_dump_json(indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_high_risk_servers() -> str:
        """Return servers with composite risk score ≥ 7.0 as a JSON list of name/score objects.

        Coverage warnings, including project_config_not_connected, are returned
        by scan_mcp_servers and the get_*_findings tools' warnings key.
        """
        report = await _scan(ScanOptions())
        report = report.redacted()
        high_risk = [
            {"name": a.server.name, "score": a.risk_score.composite if a.risk_score else 0.0}
            for a in report.audits
            if a.risk_score is not None and a.risk_score.composite >= 7.0
        ]
        return json.dumps(high_risk, indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def check_server(name: str) -> str:
        """Audit one uniquely named server. Returns JSON audit result."""
        parse_errors: list[ConfigParseError] = []
        servers = discover_all_configs(None, parse_errors)
        if parse_errors:
            raise ToolError(
                f"Cannot resolve server '{name}': discovery is incomplete "
                f"({len(parse_errors)} config parse error(s))"
            )

        matches = [server for server in servers if server.name == name]
        if not matches:
            raise ToolError(f"Server '{name}' not found")
        if len(matches) != 1:
            raise ToolError(
                f"Server '{name}' is ambiguous: {len(matches)} discovered entries share this name"
            )

        report = await _scan(ScanOptions(pin_check=True), servers=[matches[0]])
        report = report.redacted()
        payload = report.audits[0].model_dump(mode="json")
        payload["warnings"] = [warning.model_dump() for warning in report.warnings]
        return json.dumps(payload, indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_injection_findings() -> str:
        """Return all prompt injection findings across all servers. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(inject_check=True))
        report = report.redacted()
        all_findings = []
        for audit in report.audits:
            for f in audit.injection_findings:
                all_findings.append(
                    {
                        "server": audit.server.name,
                        "tool": f.tool_name,
                        "severity": f.severity,
                        "pattern": f.pattern_name,
                        "instruction_pattern": f.instruction_pattern,
                        "hunt_targets": f.hunt_targets,
                        "field_path": f.field_path,
                        "description": f.description,
                        "matched_text": f.matched_text,
                    }
                )
        return _findings_payload(report, all_findings)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_ssrf_findings() -> str:
        """Return all SSRF findings across all servers. Returns JSON `{findings, warnings}`."""
        report = await _scan(ScanOptions(ssrf_check=True))
        report = report.redacted()
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
        report = report.redacted()
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
        report = report.redacted()
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
        report = report.redacted()
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
                        "annotation_changes": f.annotation_changes,
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
        report = report.redacted()
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
        report = report.redacted()
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
        report = report.redacted()
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
        report = report.redacted()
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
    async def list_discovered_servers() -> str:
        """Return names and clients of all discovered MCP servers. Returns JSON list."""
        servers = discover_all_configs(None)
        report = (await run_scan(ScanOptions(skip_connect=True), servers=servers)).redacted()
        return json.dumps(
            [
                {
                    "name": a.server.name,
                    "client": a.server.client.value,
                    "transport": a.server.transport.value,
                }
                for a in report.audits
            ],
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
