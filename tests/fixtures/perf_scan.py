"""Disposable scanner process: CLI wall/RSS plus permission-analysis timing."""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path
from unittest.mock import patch

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.cli import main
from mcp_audit.models import PermissionFinding, ToolInfo


def run() -> None:
    analysis_seconds = 0.0
    original = PermissionAnalyzer.analyze_server

    def timed(self: PermissionAnalyzer, tools: list[ToolInfo]) -> list[PermissionFinding]:
        nonlocal analysis_seconds
        start = time.perf_counter()
        try:
            return original(self, tools)
        finally:
            analysis_seconds += time.perf_counter() - start

    metrics_path = Path(sys.argv[1])
    start = time.perf_counter()
    try:
        with patch.object(PermissionAnalyzer, "analyze_server", timed):
            main(args=sys.argv[2:], standalone_mode=False)
    finally:
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        metrics_path.write_text(
            json.dumps(
                {
                    "cli_seconds": time.perf_counter() - start,
                    "analysis_seconds": analysis_seconds,
                    "peak_rss_bytes": rss if sys.platform == "darwin" else rss * 1024,
                }
            )
        )


if __name__ == "__main__":
    run()
