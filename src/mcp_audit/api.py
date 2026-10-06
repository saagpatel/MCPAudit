"""In-memory, no-spawn config-only scan API.

This is the library entrypoint behind hosted callers — e.g. a "paste your MCP
config -> trust score" page — that hold a config in memory rather than on disk.

Its load-bearing guarantee: it reuses the exact scan engine
(:func:`mcp_audit.engine.run_scan` in ``skip_connect`` / ``config_only`` mode)
while NEVER spawning a server process and NEVER making a network request. Only
declared configuration is inferred — the same conservative static analysis as
``mcp-audit scan --config <file> --config-only --skip-connect``.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

import anyio

from mcp_audit.discovery.base import ConfigParseError
from mcp_audit.models import AuditReport, ServerConfig

# Synthetic ``config_path`` for pasted, file-less configs. Surfaces in findings
# in place of a real on-disk path.
_PASTED_SOURCE = "<pasted-config>"


def parse_config(
    config: dict[str, Any] | str | bytes,
    *,
    source: str = _PASTED_SOURCE,
    parse_errors: list[ConfigParseError] | None = None,
) -> list[ServerConfig]:
    """Parse an in-memory MCP client config into :class:`ServerConfig` objects.

    Accepts a parsed mapping or raw JSON text/bytes. Performs no filesystem
    access and spawns nothing. Reuses the discovery layer's format handling
    (``mcpServers``, ``servers``, ``mcp.servers``, and ``projects.*.mcpServers``) so the
    result matches a file-based scan of the same config exactly.

    Raises:
        ValueError: if the input is invalid or has no supported server map.
    """
    if isinstance(config, (bytes, bytearray)):
        config = config.decode("utf-8-sig")
    if isinstance(config, str):
        try:
            from mcp_audit.discovery._config import decode_config
            from mcp_audit.models import ClientType

            data: object = decode_config(config, source, ClientType.CLAUDE_CODE, parse_errors, jsonc=True)
        except ConfigParseError as exc:
            raise ValueError(exc.reason) from exc
    else:
        data = config

    if not isinstance(data, dict):
        raise ValueError('config must be a JSON object mapping (e.g. {"mcpServers": {...}})')

    # Imported lazily so importing this module stays cheap for callers that only
    # need the parse/scan entrypoints.
    from mcp_audit.discovery.claude_code import parse_mapping

    try:
        return parse_mapping(data, source, parse_errors, sniff_format=True)
    except ConfigParseError as exc:
        raise ValueError(exc.reason) from exc


async def scan_config_only(
    config: dict[str, Any] | str | bytes,
    *,
    source: str = _PASTED_SOURCE,
) -> AuditReport:
    """Run a static, no-spawn, no-network scan of an in-memory MCP config.

    Equivalent to ``mcp-audit scan --config <file> --config-only --skip-connect``
    operating on a config already in memory: every server is analyzed from its
    declared configuration only. No server process is launched and no network
    request is made.
    """
    from mcp_audit.engine import ScanOptions, run_scan

    parse_errors: list[ConfigParseError] = []
    servers = parse_config(config, source=source, parse_errors=parse_errors)
    return await run_scan(
        ScanOptions(skip_connect=True, config_only=True),
        servers=servers,
        parse_errors=parse_errors,
    )


def scan_config_only_dict(
    config: dict[str, Any] | str | bytes,
    *,
    source: str = _PASTED_SOURCE,
    redact: bool = True,
) -> dict[str, Any]:
    """Synchronous wrapper returning a JSON-serializable report dict.

    Intended for hosted/serverless callers running in a synchronous request
    handler. ``redact=True`` (the default) scrubs host and username identifiers
    from the result via the same pass as ``scan --redact`` — the scanning host's
    identity must never leak into a user-facing report.
    Credential redaction always applies, including when ``redact=False``.

    Raises:
        RuntimeError: if called from within a running event loop. Use the async
            :func:`scan_config_only` directly in that case.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass  # No running loop — safe to drive our own via anyio.run.
    else:
        raise RuntimeError(
            "scan_config_only_dict() is synchronous and cannot run inside an active "
            "event loop; await scan_config_only() instead and serialize the result."
        )

    report = anyio.run(partial(scan_config_only, config, source=source))
    return report.redacted(identifiers=redact).model_dump(mode="json")
