"""--canary-observe: sandboxed canary calls checked against read-only and closed-world hints."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import pytest

from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ObservedCall, ServerAudit, ToolAnnotations, TransportType
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
    assert review == [_REVIEW_PREFIX + "weather -> telemetry.example.invalid."]
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


@macos_only
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
        assert call.network_unknown == 1 and call.network_hosts == []
        assert (
            observe.network_review_note([call])
            == _REVIEW_PREFIX + "status -> 1 request(s) to an unknown destination."
        )
        # A tool that does not claim closed-world is not listed for review.
        start = await trap.begin()
        _proxy_request(trap, b"GET http://exfil.example.com/ HTTP/1.1")
        open_world = ToolAnnotations(read_only_hint=True, open_world_hint=True)
        assert (
            observe.network_review_note([await trap.end(start, "search", 2, open_world, errored=False)]) == ""
        )
    finally:
        trap.close()


_REVIEW_PREFIX = (
    "For review: tools declaring openWorldHint=false made proxied network requests. This can be a "
    "fixed private backend inside a closed domain, so it is not reported as a finding: "
)


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
        assert network_review_note([call]) == _REVIEW_PREFIX + "status -> zz-external.example.com."
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

    quiet = ObservedCall(tool_name="c", call=5)  # a tool that writes nothing keeps "every tool wrote" off
    calls = [
        call(1, "a", logs),
        call(2, "a", logs),
        call(3, "b", logs | caches),
        call(4, "b", logs | caches),
        quiet,
    ]
    assert not set(calls[2].files_changed) & logs  # the report alone would hide the overlap
    confirm_contradictions(calls)
    assert [c.verdict for c in calls[:2]] == ["inconclusive", "inconclusive"]
    assert [c.verdict for c in calls[2:4]] == [
        "contradiction",
        "contradiction",
    ]  # b also writes its own files


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


@pytest.mark.anyio
async def test_unsupported_platform_is_refused_not_run_unsandboxed(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.engine as engine

    monkeypatch.setattr(engine, "observation_supported", lambda _stdio: False)
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    with pytest.raises(ValueError, match="needs macOS"):
        await run_scan(ScanOptions(canary_check=True, canary_calls=1, canary_observe=True), servers=[config])


@pytest.mark.anyio
async def test_permission_error_vetoes_a_write_in_the_same_call() -> None:
    """A denied read that also writes an error log must not become MCP055."""
    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        (trap.writable / "state" / "errors.log").write_text("denied")
        trap.stderr.feed(b"PermissionError: [Errno 13] Permission denied")
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.verdict == "inconclusive" and call.contradicted_hints == []
    finally:
        trap.close()


@pytest.mark.anyio
async def test_equal_length_overwrite_with_restored_mtime_is_seen() -> None:
    import os as _os

    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    target = trap.writable / "tmp" / "settings.json"
    target.write_text("aaaa")
    try:
        start = await trap.begin()
        before = target.stat()
        target.write_text("bbbb")  # same length
        _os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # mtime restored
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.files_changed == ["tmp/settings.json"] and call.contradicted_hints == ["readOnlyHint"]
    finally:
        trap.close()


@pytest.mark.anyio
async def test_permission_change_is_seen() -> None:
    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    target = trap.writable / "tmp" / "key.pem"
    target.write_text("x")
    try:
        start = await trap.begin()
        target.chmod(0o644 if (target.stat().st_mode & 0o777) != 0o644 else 0o600)
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.files_changed == ["tmp/key.pem"]
    finally:
        trap.close()


def test_one_tool_with_a_lazily_created_log_is_not_pinned_on_it() -> None:
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def hit(call: int, changed: set[str], created: set[str]) -> ObservedCall:
        observed = ObservedCall(
            tool_name="status", call=call, verdict="contradiction", contradicted_hints=["readOnlyHint"]
        )
        observed._changed_paths = changed
        observed._created_paths = created
        return observed

    lazy_log = [hit(1, {"state/access.log"}, {"state/access.log"}), hit(2, {"state/access.log"}, set())]
    confirm_contradictions(lazy_log)
    assert {c.verdict for c in lazy_log} == {"inconclusive"}
    new_files = [hit(1, {"tmp/a"}, {"tmp/a"}), hit(2, {"tmp/b"}, {"tmp/b"})]  # a new entry every call
    confirm_contradictions(new_files)
    assert {c.verdict for c in new_files} == {"contradiction"}


@pytest.mark.anyio
async def test_direct_connector_refuses_unsupported_stdio_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Callers that bypass the CLI and run_scan checks still never get an unsandboxed launch."""
    import mcp_audit.connector as connector

    async def must_not_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("server launched without its sandbox")

    monkeypatch.setattr(connector, "observation_supported", lambda _stdio: False)
    monkeypatch.setattr(connector.ServerConnector, "_connect_stdio", must_not_connect)
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    audit = await connector.ServerConnector(timeout=10).connect(config, canary_calls=2, canary_observe=True)
    assert audit.connection_status == "failed"
    assert audit.canary is not None and any("not started" in w for w in audit.canary.warnings)


@pytest.mark.anyio
async def test_unparsed_only_traffic_is_an_unknown_destination_not_a_host() -> None:
    from mcp_audit.observe import ObservationTrap, network_review_note

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        _proxy_request(trap, b"GET /health HTTP/1.1")
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert (
            network_review_note([call])
            == _REVIEW_PREFIX + "status -> 1 request(s) to an unknown destination."
        )
    finally:
        trap.close()


def test_every_read_only_tool_writing_is_server_level() -> None:
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def hit(call: int, tool: str) -> ObservedCall:
        observed = ObservedCall(
            tool_name=tool, call=call, verdict="contradiction", contradicted_hints=["readOnlyHint"]
        )
        observed._changed_paths = {f"state/req-{call}.log"}  # a new file per request
        observed._created_paths = set(observed._changed_paths)
        return observed

    calls = [hit(1, "a"), hit(2, "a"), hit(3, "b"), hit(4, "b")]
    confirm_contradictions(calls)
    assert {c.verdict for c in calls} == {"inconclusive"}
    assert "every tool whose calls could be judged" in calls[0].inconclusive_reason


def test_per_request_server_logs_are_server_level_even_without_every_repeat() -> None:
    """Default rotation A,A,B,B,C: C never gets a repeat, yet every read-only tool wrote."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def hit(call: int, tool: str) -> ObservedCall:
        observed = ObservedCall(
            tool_name=tool, call=call, verdict="contradiction", contradicted_hints=["readOnlyHint"]
        )
        observed._changed_paths = {f"state/req-{call}.log"}
        observed._created_paths = set(observed._changed_paths)
        return observed

    rotation = [hit(1, "a"), hit(2, "a"), hit(3, "b"), hit(4, "b"), hit(5, "c")]
    confirm_contradictions(rotation)
    assert {c.verdict for c in rotation} == {"inconclusive"}
    cut_short = [hit(1, "a"), hit(2, "a"), hit(3, "b")]  # session ended before b's repeat
    confirm_contradictions(cut_short)
    assert {c.verdict for c in cut_short} == {"inconclusive"}


@pytest.mark.anyio
async def test_unknown_destinations_are_counted_from_the_raw_window() -> None:
    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    try:
        start = await trap.begin()
        for _ in range(3):
            _proxy_request(trap, b"GET /health HTTP/1.1")
        for index in range(60):  # more distinct hosts than the report keeps
            _proxy_request(trap, f"GET http://h{index:02d}.example.net/ HTTP/1.1".encode())
        call = await trap.end(start, "status", 1, _closed(), errored=False)
        assert call.network_unknown == 3
        assert len(call.network_hosts) == 50
    finally:
        trap.close()


@macos_only
@pytest.mark.anyio
async def test_an_effect_on_the_last_budgeted_call_gets_its_confirming_repeat() -> None:
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    report = await run_scan(
        ScanOptions(canary_check=True, canary_calls=1, canary_observe=True, timeout=60), servers=[config]
    )
    audit = report.audits[0]
    assert audit.canary is not None
    # The extra call happened: a budget of one still produced the confirming repeat.
    assert [c.tool_name for c in audit.canary.observed_calls] == ["cache_info", "cache_info"]
    assert audit.canary.completed_calls == 2
    # With one tool exercised, two writes to the same file stay unattributed (server-level guard).
    assert {c.verdict for c in audit.canary.observed_calls} == {"inconclusive"}
    assert "one tool exercised" in audit.canary.observed_calls[0].inconclusive_reason


@pytest.mark.anyio
@pytest.mark.parametrize("calls", [None, 0])
async def test_observe_without_a_call_budget_never_launches(
    monkeypatch: pytest.MonkeyPatch, calls: int | None
) -> None:
    import mcp_audit.connector as connector

    async def must_not_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("server launched without its sandbox")

    monkeypatch.setattr(connector.ServerConnector, "_connect_stdio", must_not_connect)
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    kwargs: dict[str, object] = {"canary_observe": True}
    if calls is not None:
        kwargs["canary_calls"] = calls
    with pytest.raises(ValueError, match="positive canary call budget"):
        await connector.ServerConnector(timeout=10).connect(config, **kwargs)  # type: ignore[arg-type]


def test_a_safe_marked_tool_writing_too_makes_it_server_level() -> None:
    """One read-only tool plus one operator-marked tool, both writing a new file per request."""
    from mcp_audit.models import ObservedCall
    from mcp_audit.observe import confirm_contradictions

    def call(number: int, tool: str, read_only: bool) -> ObservedCall:
        observed = ObservedCall(
            tool_name=tool,
            call=number,
            verdict="contradiction" if read_only else "consistent",
            contradicted_hints=["readOnlyHint"] if read_only else [],
        )
        observed._changed_paths = {f"state/req-{number}.log"}
        observed._created_paths = set(observed._changed_paths)
        return observed

    calls = [call(1, "a", True), call(2, "a", True), call(3, "c", False)]
    confirm_contradictions(calls)
    assert [c.verdict for c in calls[:2]] == ["inconclusive", "inconclusive"]


@macos_only
@pytest.mark.anyio
async def test_analysis_timeout_keeps_finished_observations(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timeout at the very first analysis step discards analysis, never finished observations."""
    import mcp_audit.engine as engine

    def time_out_at_once(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("analysis budget exhausted")

    monkeypatch.setattr(engine, "analysis_budget", time_out_at_once)
    config = make_server_config(name="liar", command=sys.executable, args=[FIXTURE, "liar"])
    report = await run_scan(
        ScanOptions(canary_check=True, canary_calls=12, canary_observe=True, timeout=90), servers=[config]
    )
    audit = report.audits[0]
    assert audit.connection_status == "timeout"
    assert audit.canary is not None and audit.canary.observed_calls
    assert {(f.tool_name, f.rule_id) for f in audit.annotation_findings} == {
        ("cache_info", "MCP055"),
        ("status", "MCP055"),
    }


def test_unusable_temp_path_fails_trap_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import tempfile

    from mcp_audit.observe import ObservationTrap

    odd = tmp_path / 'quote"dir'
    odd.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(odd))
    with pytest.raises(OSError, match="sandbox profile"):
        ObservationTrap()


@macos_only
def test_sandbox_denies_device_writes_except_dev_null(tmp_path: Path) -> None:
    """Writes to a test-owned pseudo-terminal are denied; /dev/null still works."""
    import subprocess

    from mcp_audit.observe import SANDBOX_EXEC, sandbox_profile

    trap = (tmp_path / "trap").resolve()
    trap.mkdir()
    profile = tmp_path / "profile.sb"
    profile.write_text(sandbox_profile(trap, 9))
    leader, follower = os.openpty()
    try:
        tty = os.ttyname(follower)
        probe = (
            "import sys\n"
            "open('/dev/null', 'w').write('ok')\n"
            "try:\n"
            "    open(sys.argv[1], 'w').write('escape')\n"
            "    print('tty-write-allowed')\n"
            "except PermissionError:\n"
            "    print('tty-write-denied')\n"
        )
        result = subprocess.run(
            [SANDBOX_EXEC, "-f", str(profile), sys.executable, "-I", "-c", probe, tty],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        assert result.stdout.strip() == "tty-write-denied"
    finally:
        os.close(leader)
        os.close(follower)


def test_cli_warns_when_timeout_is_too_short_for_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from click.testing import CliRunner

    import mcp_audit.check_cli as check_cli
    from mcp_audit.cli import main

    monkeypatch.setattr(check_cli, "observation_supported", lambda _stdio: True)
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {}}')
    result = CliRunner().invoke(
        main,
        [
            "check",
            "--config",
            str(config),
            "--config-only",
            "--connect-all",
            "--canary-check",
            "--canary-observe",
            "--timeout",
            "10",
            "--override-config",
            "/dev/null",
        ],
    )
    assert "--canary-observe adds about" in result.output


@macos_only
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores folder permissions")
def test_trap_close_removes_folders_a_server_locked() -> None:
    from mcp_audit.observe import ObservationTrap

    trap = ObservationTrap()
    locked = trap.writable / "state" / "locked"
    (locked / "inner").mkdir(parents=True)
    (locked / "inner" / "data").write_text("x")
    (locked / "inner").chmod(0)
    locked.chmod(0)
    trap.close()
    assert not trap.root.exists()
    assert trap.cleanup_warning == ""


@macos_only
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores folder permissions")
def test_trap_close_never_chmods_through_a_link(tmp_path: Path) -> None:
    from mcp_audit.observe import ObservationTrap

    outside = tmp_path / "outside"
    outside.mkdir()
    outside.chmod(0o500)
    trap = ObservationTrap()
    (trap.writable / "cache" / "link").symlink_to(outside, target_is_directory=True)
    try:
        trap.close()
        assert outside.stat().st_mode & 0o777 == 0o500
        assert outside.exists() and not trap.root.exists()
    finally:
        outside.chmod(0o700)


def test_trap_close_warns_when_something_remains(monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil

    import mcp_audit.observe as observe

    real_rmtree = shutil.rmtree
    trap = observe.ObservationTrap()
    monkeypatch.setattr("shutil.rmtree", lambda *_args, **_kwargs: None)
    try:
        trap.close()
        assert "could not fully remove" in trap.cleanup_warning
        assert str(trap.root) in trap.cleanup_warning
    finally:
        real_rmtree(trap.root)


def _effect(number: int, tool: str, *, errored: bool = False, wrote: bool = True) -> ObservedCall:
    observed = ObservedCall(
        tool_name=tool,
        call=number,
        errored=errored,
        verdict="contradiction" if wrote else "inconclusive",
        contradicted_hints=["readOnlyHint"] if wrote else [],
    )
    if wrote:
        observed._changed_paths = {f"state/req-{number}.log"}  # a new file per request
        observed._created_paths = set(observed._changed_paths)
    return observed


def test_errored_call_without_effect_does_not_count_against_server_level_writes() -> None:
    """a and c write a new file per request; b errored before anything was written."""
    from mcp_audit.observe import confirm_contradictions

    calls = [
        _effect(1, "a"),
        _effect(2, "a"),
        _effect(3, "b", errored=True, wrote=False),
        _effect(4, "c"),
        _effect(5, "c"),
    ]
    confirm_contradictions(calls)
    assert all(not c.contradicted_hints for c in calls)
    assert "every tool whose calls could be judged" in calls[0].inconclusive_reason


def test_unscanned_call_does_not_count_against_server_level_writes() -> None:
    from mcp_audit.observe import confirm_contradictions

    unscanned = _effect(3, "b", wrote=False)
    unscanned._scanned = False
    calls = [_effect(1, "a"), _effect(2, "a"), unscanned, _effect(4, "c"), _effect(5, "c")]
    confirm_contradictions(calls)
    assert all(not c.contradicted_hints for c in calls)


def test_a_tool_that_succeeded_without_writing_keeps_the_liar_pinned() -> None:
    from mcp_audit.observe import confirm_contradictions

    calls = [_effect(1, "a"), _effect(2, "a"), _effect(3, "b", wrote=False), _effect(4, "c"), _effect(5, "c")]
    confirm_contradictions(calls)
    assert [c.verdict for c in calls] == [
        "contradiction",
        "contradiction",
        "inconclusive",
        "contradiction",
        "contradiction",
    ]


def test_errored_sibling_leaves_one_judged_tool_under_the_one_tool_guard() -> None:
    """A log created on a's first call and appended on its second, beside an erroring b."""
    from mcp_audit.observe import confirm_contradictions

    first, second = _effect(1, "a"), _effect(2, "a")
    first._changed_paths = first._created_paths = {"state/server.log"}
    second._changed_paths, second._created_paths = {"state/server.log"}, set()
    calls = [first, second, _effect(3, "b", errored=True, wrote=False)]
    confirm_contradictions(calls)
    assert {c.verdict for c in calls[:2]} == {"inconclusive"}
    assert "one tool exercised" in calls[0].inconclusive_reason


@macos_only
def test_sandbox_allows_only_the_proxy_port_on_loopback(tmp_path: Path) -> None:
    import socket
    import subprocess

    from mcp_audit.observe import SANDBOX_EXEC, sandbox_profile

    trap = (tmp_path / "trap").resolve()
    trap.mkdir()
    with socket.create_server(("127.0.0.1", 0)) as proxy, socket.create_server(("127.0.0.1", 0)) as other:
        profile = tmp_path / "profile.sb"
        profile.write_text(sandbox_profile(trap, proxy.getsockname()[1]))
        probe = (
            "import socket, sys\n"
            "for port in sys.argv[1:]:\n"
            "    try:\n"
            "        socket.create_connection(('127.0.0.1', int(port)), timeout=5).close()\n"
            "        print('allowed')\n"
            "    except OSError:\n"
            "        print('denied')\n"
        )
        result = subprocess.run(
            [
                SANDBOX_EXEC,
                "-f",
                str(profile),
                sys.executable,
                "-I",
                "-c",
                probe,
                str(proxy.getsockname()[1]),
                str(other.getsockname()[1]),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    assert result.stdout.split() == ["allowed", "denied"]


def test_sandbox_profile_rejects_an_invalid_proxy_port(tmp_path: Path) -> None:
    from mcp_audit.observe import sandbox_profile

    with pytest.raises(ValueError, match="proxy port"):
        sandbox_profile(tmp_path, 0)


@macos_only
@pytest.mark.anyio
async def test_cleanup_warning_reaches_the_report_without_changing_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_audit.observe as observe

    real_close = observe.ObservationTrap.close

    def close_leaving_a_note(self: observe.ObservationTrap) -> None:
        real_close(self)
        self.cleanup_warning = "Canary observation could not fully remove its temporary folder x."

    baseline = await _observed("honest")
    monkeypatch.setattr(observe.ObservationTrap, "close", close_leaving_a_note)
    audit = await _observed("honest")
    assert audit.canary is not None and baseline.canary is not None
    assert audit.canary.warnings == [
        *baseline.canary.warnings,
        "Canary observation could not fully remove its temporary folder x.",
    ]
    assert audit.canary.status == baseline.canary.status
