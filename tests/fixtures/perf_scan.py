"""Disposable scanner process: CLI wall/RSS plus permission-analysis timing."""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path
from unittest.mock import patch

from mcp_audit.agent_text import AgentText
from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.cli import main
from mcp_audit.models import PermissionFinding, ResourceInfo, SsrfFinding, ToolInfo
from mcp_audit.ssrf import SsrfDetector


def run() -> None:
    analysis_seconds = 0.0
    analysis_tool_counts: list[int] = []
    original = PermissionAnalyzer.analyze_server
    ssrf_tool_counts: list[int] = []
    ssrf_description_bytes: list[int] = []
    original_ssrf = SsrfDetector.scan_server

    def observed_ssrf(
        self: SsrfDetector, tools: list[ToolInfo], resources: list[ResourceInfo] | None = None
    ) -> list[SsrfFinding]:
        ssrf_tool_counts.append(len(tools))
        ssrf_description_bytes.extend(len((tool.description or "").encode("utf-8")) for tool in tools)
        return original_ssrf(self, tools, resources)

    def timed(
        self: PermissionAnalyzer,
        tools: list[ToolInfo],
        *,
        incomplete_reasons: list[str] | None = None,
        agent_texts: list[AgentText] | None = None,
    ) -> list[PermissionFinding]:
        nonlocal analysis_seconds
        analysis_tool_counts.append(len(tools))
        start = time.perf_counter()
        try:
            return original(self, tools, incomplete_reasons=incomplete_reasons, agent_texts=agent_texts)
        finally:
            analysis_seconds += time.perf_counter() - start

    metrics_path = Path(sys.argv[1])
    start = time.perf_counter()
    try:
        with (
            patch.object(PermissionAnalyzer, "analyze_server", timed),
            patch.object(SsrfDetector, "scan_server", observed_ssrf),
        ):
            main(args=sys.argv[2:], standalone_mode=False)
    finally:
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        metrics_path.write_text(
            json.dumps(
                {
                    "cli_seconds": time.perf_counter() - start,
                    "analysis_seconds": analysis_seconds,
                    "analysis_invocations": len(analysis_tool_counts),
                    "analysis_tool_counts": analysis_tool_counts,
                    "ssrf_tool_counts": ssrf_tool_counts,
                    "ssrf_description_bytes": ssrf_description_bytes,
                    "peak_rss_bytes": rss if sys.platform == "darwin" else rss * 1024,
                }
            )
        )


if __name__ == "__main__":
    run()
