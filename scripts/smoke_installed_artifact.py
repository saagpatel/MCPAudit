#!/usr/bin/env python3
"""Exercise the installed distribution against a real local MCP stdio session."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio

from mcp_audit.connector import ServerConnector
from mcp_audit.models import ClientType, ServerConfig


async def _smoke() -> None:
    root = Path(__file__).resolve().parents[1]
    config = ServerConfig(
        name="release-smoke",
        client=ClientType.CLAUDE_CODE,
        config_path=str(root / "tests/fixtures/release-smoke.json"),
        command=sys.executable,
        args=[str(root / "tests/fixtures/mock_server.py")],
    )
    audit = await ServerConnector(timeout=15.0).connect(config)
    if audit.connection_status != "connected":
        raise RuntimeError(f"connected artifact smoke failed: {audit.connection_error}")
    if {tool.name for tool in audit.tools} != {
        "execute_command",
        "read_file",
        "write_file",
    }:
        raise RuntimeError("connected artifact smoke returned the wrong tools")
    if [prompt.name for prompt in audit.prompts] != ["summarize_file"]:
        raise RuntimeError("connected artifact smoke returned the wrong prompts")
    if [resource.name for resource in audit.resources] != ["example"]:
        raise RuntimeError("connected artifact smoke returned the wrong resources")


if __name__ == "__main__":
    anyio.run(_smoke)
