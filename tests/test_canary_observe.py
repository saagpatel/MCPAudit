"""--canary-observe: sandboxed canary calls checked against read-only and closed-world hints."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ServerAudit, TransportType
from mcp_audit.observe import (
    UNSUPPORTED_WARNING,
    StderrScanner,
    _request_host,
    _snapshot,
    is_loopback,
    observation_supported,
)
from tests.conftest import make_server_config

FIXTURE = str(Path(__file__).parent / "fixtures" / "annotation_liar_server.py")
macos_only = pytest.mark.skipif(not observation_supported(True), reason="needs macOS sandbox-exec")


@pytest.fixture(autouse=True)
def _private_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Servers inherit HOME; a sandbox regression must never write to the developer's home."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


async def _observed(mode: str) -> ServerAudit:
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, mode])
    report = await run_scan(
        ScanOptions(canary_check=True, canary_calls=6, canary_observe=True, timeout=30), servers=[config]
    )
    return report.audits[0]


@macos_only
@pytest.mark.anyio
async def test_observed_lies_become_mcp055_and_control_stays_clean() -> None:
    audit = await _observed("liar")
    assert audit.canary is not None and audit.canary.observed
    verdicts = {c.tool_name: (c.verdict, tuple(c.contradicted_hints)) for c in audit.canary.observed_calls}
    assert verdicts == {
        "cache_info": ("contradiction", ("readOnlyHint",)),
        "status": ("contradiction", ("readOnlyHint",)),
        "weather": ("contradiction", ("openWorldHint",)),
        "profile": ("inconclusive", ()),
        "local_status": ("consistent", ()),
        "clock": ("consistent", ()),
    }
    observed = {(f.tool_name, f.hint) for f in audit.annotation_findings if f.rule_id == "MCP055"}
    assert observed == {
        ("cache_info", "readOnlyHint"),
        ("status", "readOnlyHint"),
        ("weather", "openWorldHint"),
    }
    weather = next(c for c in audit.canary.observed_calls if c.tool_name == "weather")
    assert weather.network_hosts == ["telemetry.example.invalid"]
    profile = next(c for c in audit.canary.observed_calls if c.tool_name == "profile")
    assert profile.blocked_operations and "permission error" in profile.inconclusive_reason
    assert not (Path.home() / ".mcp-audit-observe-fixture").exists()  # the sandbox blocked it
    # Inconclusive calls are surfaced and make coverage partial.
    assert audit.canary.status == "partial"
    assert any("inconclusive" in w and "profile" in w for w in audit.canary.warnings)


@macos_only
@pytest.mark.anyio
async def test_honest_server_has_no_observed_findings() -> None:
    audit = await _observed("honest")
    assert audit.canary is not None and audit.canary.observed
    assert {c.verdict for c in audit.canary.observed_calls} == {"consistent"}
    assert not [f for f in audit.annotation_findings if f.rule_id == "MCP055"]


@pytest.mark.anyio
async def test_http_transport_reports_observation_unsupported() -> None:
    assert not observation_supported(False)
    config = make_server_config(
        name="remote", command=None, transport=TransportType.HTTP, url="http://127.0.0.1:9/mcp"
    )
    report = await run_scan(
        ScanOptions(canary_check=True, canary_calls=1, canary_observe=True, timeout=3), servers=[config]
    )
    canary = report.audits[0].canary
    assert canary is not None and not canary.observed
    assert UNSUPPORTED_WARNING in canary.warnings


@pytest.mark.anyio
async def test_observe_requires_canary_check() -> None:
    with pytest.raises(ValueError, match="--canary-observe requires --canary-check"):
        await run_scan(ScanOptions(canary_observe=True), servers=[])


def test_stderr_scanner_counts_markers_split_across_chunks() -> None:
    scanner = StderrScanner()
    scanner.feed(b"Traceback ... PermissionError: [Errno 1] Operation not perm")
    scanner.feed(b"itted: '/x'\nPermission")
    scanner.feed(b"Error again\n")
    assert scanner.count == 3
    node = StderrScanner()
    node.feed(b"Error: EPERM: operation not permitted, open '/x'\n")
    assert node.count == 2  # "eperm" and "operation not permitted"


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("localhost:8080", True),
        ("127.0.0.1", True),
        ("[::1]:80", True),
        ("api.example.com", False),
        ("10.0.0.1:5432", False),
    ],
)
def test_loopback_hosts_are_closed_world(host: str, loopback: bool) -> None:
    assert is_loopback(host) is loopback


def test_snapshot_caps_large_traps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.observe as observe

    for index in range(5):
        (tmp_path / f"f{index}").write_text("x")
    monkeypatch.setattr(observe, "MAX_SNAPSHOT_FILES", 3)
    assert _snapshot(tmp_path) is None


@pytest.mark.parametrize(
    ("line", "host"),
    [
        ("GET http://user:secret@api.example.com/v1?token=abc HTTP/1.1", "api.example.com"),
        ("GET http://api.example.com?token=abc HTTP/1.1", "api.example.com"),
        ("GET http://u:p/w@api.example.com/ HTTP/1.1", ""),
        ("CONNECT api.example.com:443 HTTP/1.1", "api.example.com:443"),
        ("GET http://[::1]:8080/x HTTP/1.1", "[::1]:8080"),
        ("GET http://<script>/ HTTP/1.1", ""),
        ("garbage", ""),
    ],
)
def test_proxy_keeps_hosts_only(line: str, host: str) -> None:
    assert _request_host(line) == host


def test_failing_stderr_observer_does_not_stop_the_drain() -> None:
    from mcp_audit.connector import _capture_stderr, _StderrTail

    calls: list[bytes] = []

    def explode(chunk: bytes) -> None:
        calls.append(chunk)
        raise RuntimeError("observer bug")

    tail = _StderrTail()
    with _capture_stderr("fixture", tail, explode) as errlog:
        errlog.write("first\n")
        errlog.flush()
        errlog.write("second\n" * 2000)  # more than a pipe buffer: a stalled drain would block here
        errlog.flush()
    assert len(calls) == 1
    assert tail.text.rstrip().endswith("second")


@macos_only
@pytest.mark.anyio
async def test_sarif_lists_mcp055_only_when_observed() -> None:
    from mcp_audit.sarif import SarifGenerator

    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    report = await run_scan(
        ScanOptions(canary_check=True, canary_calls=6, canary_observe=True, timeout=30), servers=[config]
    )
    run = SarifGenerator().generate(report)["runs"][0]
    assert "MCP055" in {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    observed = [r for r in run["results"] if r["ruleId"] == "MCP055"]
    assert len(observed) == 3 and all(r["level"] == "error" for r in observed)  # profile is inconclusive
    assert all("sandboxed canary call" in r["message"]["text"] for r in observed)

    report.audits[0].annotation_findings = []
    plain = SarifGenerator().generate(report)["runs"][0]["tool"]["driver"]["rules"]
    assert "MCP055" not in {rule["id"] for rule in plain}
