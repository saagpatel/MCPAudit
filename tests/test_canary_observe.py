"""--canary-observe: sandboxed canary calls checked against read-only and closed-world hints."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import pytest

from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ServerAudit, ToolAnnotations, TransportType
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
        ScanOptions(canary_check=True, canary_calls=12, canary_observe=True, timeout=90), servers=[config]
    )
    return report.audits[0]


@macos_only
@pytest.mark.anyio
async def test_observed_lies_become_mcp055_and_control_stays_clean() -> None:
    audit = await _observed("liar")
    assert audit.canary is not None and audit.canary.observed
    verdicts: dict[str, set[tuple[str, tuple[str, ...]]]] = {}
    for c in audit.canary.observed_calls:
        verdicts.setdefault(c.tool_name, set()).add((c.verdict, tuple(c.contradicted_hints)))
    assert verdicts == {
        "cache_info": {("contradiction", ("readOnlyHint",))},
        "status": {("contradiction", ("readOnlyHint",))},
        "weather": {("consistent", ())},  # network is evidence for review, not a contradiction
        "profile": {("inconclusive", ())},
        "local_status": {("consistent", ())},
        "clock": {("consistent", ())},
    }
    # Each liar was re-called immediately, and the repeat confirmed it.
    calls = [c.tool_name for c in audit.canary.observed_calls]
    for name in ("cache_info", "status"):
        first = calls.index(name)
        assert calls[first + 1] == name
    observed = {(f.tool_name, f.hint) for f in audit.annotation_findings if f.rule_id == "MCP055"}
    assert observed == {("cache_info", "readOnlyHint"), ("status", "readOnlyHint")}
    weather = next(c for c in audit.canary.observed_calls if c.tool_name == "weather")
    assert weather.network_hosts == ["telemetry.example.invalid"]
    review = [w for w in audit.canary.warnings if w.startswith("For review:")]
    assert len(review) == 1 and "weather -> telemetry.example.invalid" in review[0]
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
        ("api.localhost:3000", True),
        ("localhost.", True),
        ("0.0.0.0:8080", True),
        ("evil-localhost.example.com", False),
        ("[::ffff:127.0.0.1]:80", True),
    ],
)
def test_loopback_hosts_are_closed_world(host: str, loopback: bool) -> None:
    assert is_loopback(host) is loopback


def test_snapshot_caps_large_traps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.observe as observe

    for index in range(5):
        (tmp_path / f"f{index}").write_text("x")
    monkeypatch.setattr(observe, "MAX_SNAPSHOT_ENTRIES", 3)
    assert _snapshot(tmp_path) is None


def test_snapshot_cap_counts_directories_not_only_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mcp_audit.observe as observe

    for index in range(10):
        (tmp_path / f"d{index}").mkdir()
    monkeypatch.setattr(observe, "MAX_SNAPSHOT_ENTRIES", 3)
    assert _snapshot(tmp_path) is None


def test_snapshot_stops_at_its_time_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.observe as observe

    (tmp_path / "f").write_text("x")
    monkeypatch.setattr(observe, "SNAPSHOT_SECONDS", -1.0)
    assert _snapshot(tmp_path) is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads through chmod 000")
def test_unreadable_folder_makes_snapshot_unjudgeable_not_fatal(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "f").write_text("x")
    locked.chmod(0o000)
    try:
        assert _snapshot(tmp_path) is None
    finally:
        locked.chmod(0o700)


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
        ScanOptions(canary_check=True, canary_calls=12, canary_observe=True, timeout=90), servers=[config]
    )
    run = SarifGenerator().generate(report)["runs"][0]
    assert "MCP055" in {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    observed = [r for r in run["results"] if r["ruleId"] == "MCP055"]
    assert len(observed) == 2 and all(r["level"] == "error" for r in observed)  # readOnlyHint only
    assert all("sandboxed canary call" in r["message"]["text"] for r in observed)

    report.audits[0].annotation_findings = []
    plain = SarifGenerator().generate(report)["runs"][0]["tool"]["driver"]["rules"]
    assert "MCP055" not in {rule["id"] for rule in plain}


def _proxy_request(trap: object, request_line: bytes) -> None:
    import socket

    with socket.create_connection(("127.0.0.1", trap.proxy.port), timeout=5) as conn:  # type: ignore[attr-defined]
        conn.sendall(request_line + b"\r\n\r\n")
        conn.recv(256)


@pytest.mark.anyio
async def test_proxy_log_overflow_is_counted_for_review(monkeypatch: pytest.MonkeyPatch) -> None:
    """Requests past the log cap are counted, so the review note cannot silently omit them."""
    import mcp_audit.observe as observe
    from mcp_audit.models import ToolAnnotations

    monkeypatch.setattr(observe, "MAX_PROXY_LOG", 2)
    closed = ToolAnnotations(read_only_hint=True, open_world_hint=False)
    trap = observe.ObservationTrap()
    try:
        for _ in range(2):  # earlier activity fills the log
            _proxy_request(trap, b"GET http://startup.example.com/ HTTP/1.1")
        start = await trap.begin()
        _proxy_request(trap, b"GET http://exfil.example.com/ HTTP/1.1")
        call = await trap.end(start, "status", 1, closed, errored=False)
        assert call.network_unlogged == 1 and call.network_hosts == []
        assert "status -> 1 request(s) not logged" in observe.network_review_note([call])
        # A tool that does not claim closed-world is not listed for review.
        start = await trap.begin()
        _proxy_request(trap, b"GET http://exfil.example.com/ HTTP/1.1")
        open_world = ToolAnnotations(read_only_hint=True, open_world_hint=True)
        assert (
            observe.network_review_note([await trap.end(start, "search", 2, open_world, errored=False)]) == ""
        )
    finally:
        trap.close()


def _closed() -> ToolAnnotations:
    return ToolAnnotations(read_only_hint=True, open_world_hint=False)


@pytest.mark.anyio
@pytest.mark.parametrize("request_line", [b"GET http://<junk>/ HTTP/1.1", b"GET /health HTTP/1.1"])
async def test_unparsed_proxy_request_is_listed_not_accused(request_line: bytes) -> None:
    from mcp_audit.observe import UNPARSED_REQUEST, ObservationTrap

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        _proxy_request(trap, request_line)
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.network_hosts == [UNPARSED_REQUEST]
        assert call.verdict == "consistent" and call.contradicted_hints == []
    finally:
        trap.close()


@pytest.mark.anyio
async def test_empty_proxy_connection_is_not_a_request() -> None:
    import socket

    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    try:
        with socket.create_connection(("127.0.0.1", trap.proxy.port), timeout=5):
            pass  # open and drop
        await anyio.sleep(0.2)
        assert trap.proxy.position() == (0, 0)
    finally:
        trap.close()


@pytest.mark.anyio
async def test_external_host_survives_a_loopback_flood() -> None:
    from mcp_audit.observe import ObservationTrap, network_review_note

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        for port in range(1, 61):
            _proxy_request(trap, f"GET http://127.0.0.1:{port}/ HTTP/1.1".encode())
        _proxy_request(trap, b"GET http://zz-external.example.com/ HTTP/1.1")
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.verdict == "consistent"  # network never contradicts a hint
        assert call.network_hosts[0] == "zz-external.example.com"
        assert "zz-external.example.com" in network_review_note([call])
    finally:
        trap.close()


@pytest.mark.anyio
async def test_activity_just_before_a_call_is_not_pinned_on_it() -> None:
    """Startup work (or another call's delayed effect) settling into the window."""
    from mcp_audit.observe import SETTLE_SECONDS, ObservationTrap

    trap = ObservationTrap()
    try:
        async with anyio.create_task_group() as tg:

            async def late_write() -> None:
                await anyio.sleep(SETTLE_SECONDS / 2)
                (trap.writable / "tmp" / "telemetry.json").write_text("{}")

            tg.start_soon(late_write)
            start = await trap.begin()
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.verdict == "inconclusive" and "before or after" in call.inconclusive_reason
    finally:
        trap.close()


@pytest.mark.anyio
async def test_errored_call_without_effect_is_inconclusive() -> None:
    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        call = await trap.end(start, "status", 1, _closed(), errored=True)
        assert call.verdict == "inconclusive" and "errored" in call.inconclusive_reason
    finally:
        trap.close()


def test_contradiction_needs_an_adjacent_confirming_repeat() -> None:
    """Hit, clean immediate repeat, another tool, later hit: never confirmed."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def hit(call: int, tool: str = "b") -> ObservedCall:
        return ObservedCall(
            tool_name=tool, call=call, verdict="contradiction", contradicted_hints=["readOnlyHint"]
        )

    unconfirmed = [hit(1), ObservedCall(tool_name="b", call=2), ObservedCall(tool_name="a", call=3), hit(4)]
    confirm_contradictions(unconfirmed)
    assert [c.verdict for c in unconfirmed] == ["inconclusive", "consistent", "consistent", "inconclusive"]
    confirmed = [hit(1), hit(2), ObservedCall(tool_name="a", call=3), hit(4)]
    confirm_contradictions(confirmed)
    assert [c.verdict for c in confirmed] == ["contradiction", "contradiction", "consistent", "contradiction"]


def test_one_off_contradiction_is_not_pinned_without_a_repeat() -> None:
    """A delayed effect from tool A landing once in tool B's window must not accuse B."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    calls = [
        ObservedCall(tool_name="a", call=1),
        ObservedCall(
            tool_name="b",
            call=2,
            verdict="contradiction",
            contradicted_hints=["readOnlyHint"],
            files_changed_count=1,
        ),
        ObservedCall(tool_name="b", call=3),
        ObservedCall(
            tool_name="c",
            call=4,
            verdict="contradiction",
            contradicted_hints=["readOnlyHint"],
            files_changed_count=1,
        ),
    ]
    confirm_contradictions(calls)
    assert calls[1].verdict == "inconclusive" and "immediate repeat" in calls[1].inconclusive_reason
    assert calls[3].verdict == "inconclusive" and "immediate repeat" in calls[3].inconclusive_reason


@pytest.mark.anyio
async def test_sandbox_setup_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the trap cannot start, the server is never launched unsandboxed."""
    import mcp_audit.connector as connector

    def broken_trap() -> None:
        raise OSError("no temp dir")

    async def must_not_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("server launched without its sandbox")

    monkeypatch.setattr(connector, "ObservationTrap", broken_trap)
    monkeypatch.setattr(connector, "observation_supported", lambda _stdio: True)
    monkeypatch.setattr(connector.ServerConnector, "_connect_stdio", must_not_connect)
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    audit = await connector.ServerConnector(timeout=10).connect(config, canary_calls=2, canary_observe=True)
    assert audit.connection_status == "failed"
    assert audit.canary is not None and not audit.canary.observed
    assert any("not started" in w for w in audit.canary.warnings)


def test_snapshot_does_not_follow_symlinks_out_of_the_trap(tmp_path: Path) -> None:
    trap, outside = tmp_path / "trap", tmp_path / "outside"
    trap.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    (trap / "escape").symlink_to(outside, target_is_directory=True)
    snap = _snapshot(trap)
    assert snap is not None and set(snap) == {"escape"} and snap["escape"][0] == "l"


def test_snapshot_tracks_folders_and_links(tmp_path: Path) -> None:
    trap = tmp_path / "trap"
    trap.mkdir()
    before = _snapshot(trap)
    (trap / "empty").mkdir()
    (trap / "link").symlink_to("nowhere")
    after = _snapshot(trap)
    assert before == {} and after is not None and set(after) == {"empty", "link"}


def test_writes_seen_across_tools_are_server_level_not_a_tool_lie() -> None:
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def logged(call: int, tool: str) -> ObservedCall:
        return ObservedCall(
            tool_name=tool,
            call=call,
            verdict="contradiction",
            contradicted_hints=["readOnlyHint"],
            files_changed=["state/server/access.log"],
            files_changed_count=1,
        )

    calls = [logged(1, "a"), logged(2, "a"), logged(3, "b"), logged(4, "b")]
    confirm_contradictions(calls)
    assert {c.verdict for c in calls} == {"inconclusive"}
    assert all("server-level" in c.inconclusive_reason for c in calls)


def test_proxy_connection_flood_is_counted_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    import mcp_audit.observe as observe

    monkeypatch.setattr(observe, "MAX_PROXY_CONNECTIONS", 1)
    trap = observe.ObservationTrap()
    try:
        held = socket.create_connection(("127.0.0.1", trap.proxy.port), timeout=5)  # occupies the only slot
        try:
            with socket.create_connection(("127.0.0.1", trap.proxy.port), timeout=5) as excess:
                excess.settimeout(5)
                assert excess.recv(16) == b""  # closed at once
            total, logged = trap.proxy.position()
            assert total == 1 and logged == 0  # counted, so the window reads as unlogged
        finally:
            held.close()
    finally:
        trap.close()


def test_shared_writes_beyond_the_reported_ten_still_count_as_server_level() -> None:
    """Tool B's shared log paths sort after ten other files; attribution must still see them."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    logs = {f"state/log{i}" for i in range(10)}
    caches = {f"cache/a{i}" for i in range(10)}

    def call(number: int, tool: str, changed: set[str]) -> ObservedCall:
        observed = ObservedCall(
            tool_name=tool,
            call=number,
            verdict="contradiction",
            contradicted_hints=["readOnlyHint"],
            files_changed=sorted(changed)[:10],
            files_changed_count=len(changed),
        )
        observed._changed_paths = set(changed)
        return observed

    calls = [call(1, "a", logs), call(2, "a", logs), call(3, "b", logs | caches), call(4, "b", logs | caches)]
    assert not set(calls[2].files_changed) & logs  # the report alone would hide the overlap
    confirm_contradictions(calls)
    assert [c.verdict for c in calls[:2]] == ["inconclusive", "inconclusive"]
    assert [c.verdict for c in calls[2:]] == ["contradiction", "contradiction"]  # b also writes its own files


def test_one_tool_modifying_existing_files_is_not_pinned_on_it() -> None:
    """A single exercised tool cannot be separated from an append-only server log."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def hit(call: int, created: set[str]) -> ObservedCall:
        observed = ObservedCall(
            tool_name="status",
            call=call,
            verdict="contradiction",
            contradicted_hints=["readOnlyHint"],
            files_changed=["state/access.log"],
            files_changed_count=1,
        )
        observed._changed_paths = {"state/access.log"}
        observed._created_paths = created
        return observed

    appended = [hit(1, set()), hit(2, set())]
    confirm_contradictions(appended)
    assert {c.verdict for c in appended} == {"inconclusive"}
    assert "server-level logging" in appended[0].inconclusive_reason
    created = [hit(1, {"state/access.log"}), hit(2, set())]  # the tool created the file itself
    confirm_contradictions(created)
    assert {c.verdict for c in created} == {"contradiction"}
