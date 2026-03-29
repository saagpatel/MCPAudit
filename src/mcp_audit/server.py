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
        _console.print(f"[red]Could not read {config_path}: {exc}[/red]")
        return False

    if not isinstance(raw, dict):
        _console.print(f"[red]Unexpected config format in {config_path}[/red]")
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
        _console.print(f"[red]Could not write {config_path}: {exc}[/red]")
        return False


def _build_mcp_server() -> Any:
    """Build and return the FastMCP server instance with all tools registered."""
    from mcp.server import FastMCP

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
        from mcp_audit.cli import _run_scan_core
        from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

        override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
        report = await _run_scan_core(
            skip_connect=skip_connect,
            clients=None,
            timeout=10,
            extra_config=None,
            override_applier=override_applier,
        )
        return report.model_dump_json(indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_high_risk_servers() -> str:
        """Return servers with composite risk score ≥ 7.0. Returns JSON list."""
        from mcp_audit.cli import _run_scan_core
        from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

        override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
        report = await _run_scan_core(
            skip_connect=False,
            clients=None,
            timeout=10,
            extra_config=None,
            override_applier=override_applier,
        )
        high_risk = [
            {"name": a.server.name, "score": a.risk_score.composite if a.risk_score else 0.0}
            for a in report.audits
            if a.risk_score is not None and a.risk_score.composite >= 7.0
        ]
        return json.dumps(high_risk, indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def check_server(name: str) -> str:
        """Audit a single server by name. Returns JSON audit result."""
        from mcp_audit.cli import _run_scan_core
        from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

        override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
        report = await _run_scan_core(
            skip_connect=False,
            clients=None,
            timeout=10,
            extra_config=None,
            override_applier=override_applier,
        )
        audit = next((a for a in report.audits if a.server.name == name), None)
        if audit is None:
            return json.dumps({"error": f"Server '{name}' not found"})
        return audit.model_dump_json(indent=2)

    @app.tool()  # type: ignore[untyped-decorator]
    async def get_injection_findings() -> str:
        """Return all prompt injection findings across all servers. Returns JSON list."""
        from mcp_audit.cli import _run_scan_core
        from mcp_audit.injection import InjectionDetector
        from mcp_audit.overrides import DEFAULT_OVERRIDE_PATH, OverrideApplier, load_override_config

        override_applier = OverrideApplier(load_override_config(DEFAULT_OVERRIDE_PATH))
        report = await _run_scan_core(
            skip_connect=True,
            clients=None,
            timeout=10,
            extra_config=None,
            override_applier=override_applier,
        )
        detector = InjectionDetector()
        all_findings = []
        for audit in report.audits:
            findings = detector.scan_server(audit.tools)
            for f in findings:
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
        return json.dumps(all_findings, indent=2)

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
    """Write mcp-audit server entry to detected config files."""
    installed_any = False
    for config_path in _CLAUDE_DESKTOP_CONFIG_PATHS:
        if config_path.exists() and _install_to_config(config_path):
            installed_any = True

    if _CLAUDE_CODE_CONFIG_PATH.exists() and _install_to_config(_CLAUDE_CODE_CONFIG_PATH):
        installed_any = True

    if not installed_any:
        _console.print("[yellow]No Claude config files found. Add manually:[/yellow]")
        _console.print(
            '  Add to your claude_desktop_config.json or .claude.json under "mcpServers":\n'
            '  "mcp-audit": {"command": "mcp-audit", "args": ["serve"]}'
        )


async def _serve() -> None:
    app = _build_mcp_server()
    import sys as _sys

    _sys.stderr.write("mcp-audit MCP server starting on stdio...\n")
    await app.run_stdio_async()
