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
from mcp_audit.discovery import ConfigParseError
from mcp_audit.engine import _parse_extra_config
from mcp_audit.models import ClientType, PermissionFinding, ResourceInfo, SsrfFinding, ToolInfo
from mcp_audit.review_discovery import ReviewSources
from mcp_audit.ssrf import SsrfDetector


def engine_sources(
    config: Path | None,
    include_discovered: bool,
    project: Path | None,
    clients: tuple[ClientType, ...],
    *,
    scan_compatible: bool = False,
) -> ReviewSources:
    """TEST ONLY: supply explicit library stress input above check's source caps.

    This fixture bypasses only review-source admission. It proves engine and
    report behavior for a pre-parsed synthetic fleet, not CLI source admission
    at this size. Ordinary workloads still use the real check source parser.
    """
    if config is None or include_discovered or project is not None or clients or scan_compatible:
        raise ValueError("Fixture engine sources require an explicit config without discovery or filters.")
    errors: list[ConfigParseError] = []
    servers = _parse_extra_config(config, errors)
    return ReviewSources(
        servers=servers,
        errors=errors,
        paths=[(str(config), "checked: synthetic fixture engine source")],
    )


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
    argv = sys.argv[2:]
    injected_sources = "--engine-sources" in argv
    if injected_sources:
        if argv.count("--engine-sources") != 1 or argv[0] != "check" or "--config-only" not in argv:
            raise ValueError("Fixture --engine-sources requires check --config FILE --config-only.")
        argv.remove("--engine-sources")
    start = time.perf_counter()
    try:
        with (
            patch.object(PermissionAnalyzer, "analyze_server", timed),
            patch.object(SsrfDetector, "scan_server", observed_ssrf),
        ):
            if injected_sources:
                with patch("mcp_audit.check_cli.review_sources", engine_sources):
                    main(args=argv, standalone_mode=False)
            else:
                main(args=argv, standalone_mode=False)
    finally:
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        metrics_path.write_text(
            json.dumps(
                {
                    "cli_seconds": time.perf_counter() - start,
                    "source_mode": "fixture-engine-sources" if injected_sources else "check",
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
