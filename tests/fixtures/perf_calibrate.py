"""Fixed local-only process and report workloads for the hostile perf gate."""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from mcp_audit.models import AuditReport, ClientType, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.report import ReportGenerator


async def handshake(root: Path) -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-S",
        str(Path(__file__).with_name("hostile_server.py")),
        "normal",
        "--tools",
        "10",
        "--work-dir",
        str(root),
        cwd=root,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        for rid, method, params in (
            (1, "initialize", {"protocolVersion": "2025-06-18"}),
            (2, "tools/list", {}),
        ):
            process.stdin.write(
                (
                    json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n"
                ).encode()
            )
            await process.stdin.drain()
            response = json.loads(await asyncio.wait_for(process.stdout.readline(), timeout=30))
            assert response["id"] == rid and "result" in response, "Calibration handshake failed."
            if method == "tools/list":
                assert len(response["result"]["tools"]) == 10, "Calibration listing incomplete."
        process.stdin.close()
        await asyncio.wait_for(process.wait(), timeout=30)
        assert process.returncode == 0, "Calibration fixture failed."
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def process_workload(root: Path) -> float:
    start = time.perf_counter()
    for _ in range(64):
        await handshake(root)
    # Two fixed batches of 32; include spawn, imports, initialize, listing and EOF.
    for _ in range(2):
        await asyncio.gather(*(handshake(root) for _ in range(32)))
    return time.perf_counter() - start


def cpu_workload() -> float:
    # Fixed data and null output keep this about redaction/model/JSON CPU costs.
    tools = [
        ToolInfo(
            name=f"tool_{i}",
            description=("Read synthetic file contents from path. " * 16),
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        )
        for i in range(4000)
    ]
    report = AuditReport(
        scan_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        hostname="synthetic",
        os_platform="synthetic",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=len(tools),
        high_risk_servers=0,
        audits=[
            ServerAudit(
                server=ServerConfig(name="synthetic", client=ClientType.CLAUDE_CODE, config_path="synthetic"),
                connection_status="connected",
                tools=tools,
            )
        ],
        scan_duration_seconds=0,
    )
    renderer = ReportGenerator(Console(file=io.StringIO()))
    start = time.perf_counter()
    for _ in range(16):
        renderer.render_json(report, Path(os.devnull))
    return time.perf_counter() - start


if __name__ == "__main__":
    root = Path(sys.argv[1]).resolve()
    print(json.dumps({"process": asyncio.run(process_workload(root)), "cpu": cpu_workload()}))
