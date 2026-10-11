"""Opt-in negative requests against disposable synthetic loopback servers only."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.conformance_probe import BAD_ORIGIN, PROTOCOL_VERSION, run_conformance_probe
from mcp_audit.probe import MAX_BODY_BYTES, _Response
from tests.fixtures.conformance_server import ConformancePeer, ConformanceServer


@pytest.fixture(params=["mock", "http"])
def wire_transport(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def peer(
    request: pytest.FixtureRequest, wire_transport: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[ConformancePeer]:
    if wire_transport == "mock":
        fixture = ConformancePeer(getattr(request, "param", "compliant"))

        def respond(
            url: str,
            method: str,
            address: str,
            timeout: float,
            *,
            request_headers: dict[str, str],
            request_body: bytes,
        ) -> _Response:
            status, body = fixture.respond(
                {key.lower(): value for key, value in request_headers.items()}, json.loads(request_body)
            )
            return _Response(status, [], True, body[:MAX_BODY_BYTES], len(body) > MAX_BODY_BYTES)

        monkeypatch.setattr("mcp_audit.conformance_probe._request_sync", respond)
        yield fixture
        return
    with ConformanceServer(getattr(request, "param", "compliant")) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.peer
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _url(peer: ConformancePeer) -> str:
    return f"http://127.0.0.1:{peer.server_port}/mcp"


def test_opt_in_cli_probes_all_header_mismatches_and_origin(peer: ConformancePeer) -> None:
    result = CliRunner().invoke(main, ["lab", "--conformance-probe", "--url", _url(peer)])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["contract"] == "mcpaudit.conformance-probe.v1"
    assert report["modern_control"] is True
    assert [
        (o["probe"], o["variant"], o["verdict"], o["status"], o["error_code"]) for o in report["observations"]
    ] == [
        ("T7", "protocol_version", "pass", 400, -32020),
        ("T7", "method", "pass", 400, -32020),
        ("T7", "name", "pass", 400, -32020),
        ("T9", "origin", "pass", 403, -32600),
    ]
    assert len(peer.requests) == 5
    for headers, body in peer.requests:
        assert not {"authorization", "cookie", "mcp-session-id", "proxy-authorization"} & headers.keys()
        assert body["method"] in {"server/discover", "resources/read"}
    control, version, method, name, origin = peer.requests
    assert control[0]["mcp-protocol-version"] == PROTOCOL_VERSION
    assert version[0]["mcp-protocol-version"] == "2025-11-25"
    assert version[1] == control[1] == method[1] == origin[1]
    assert method[0]["mcp-method"] == "ping"
    assert name[0]["mcp-name"] == "urn:mcpaudit:header-mismatch"
    name_params = name[1]["params"]
    assert isinstance(name_params, dict)
    assert name_params["uri"] == "urn:mcpaudit:conformance-probe"
    assert origin[0]["origin"] == BAD_ORIGIN
    assert all("origin" not in headers for headers, _ in peer.requests[:-1])
    assert "private-fixture-marker" not in result.output
    assert _url(peer) not in result.output


@pytest.mark.anyio
@pytest.mark.parametrize("peer", ["accept"], indirect=True)
async def test_accepting_negative_requests_is_a_failure(peer: ConformancePeer) -> None:
    report = await run_conformance_probe(_url(peer), 2)
    observations = report["observations"]
    assert isinstance(observations, list)
    assert [o["verdict"] for o in observations] == ["fail"] * 4
    assert len(peer.requests) == 5


@pytest.mark.anyio
@pytest.mark.parametrize(
    "peer",
    ["auth", "redirect", "wrong-error", "oversized", "missing-message", "numeric-message"],
    indirect=True,
)
async def test_incomplete_rejections_remain_unknown(peer: ConformancePeer) -> None:
    report = await run_conformance_probe(_url(peer), 2)
    observations = report["observations"]
    assert isinstance(observations, list)
    assert [o["verdict"] for o in observations[:3]] == ["unknown"] * 3
    assert len(peer.requests) == 5  # No redirects, cookie follow-ups, or retries.


@pytest.mark.anyio
@pytest.mark.parametrize("peer", ["legacy"], indirect=True)
async def test_t7_requires_modern_control_but_origin_is_version_independent(peer: ConformancePeer) -> None:
    report = await run_conformance_probe(_url(peer), 2)
    observations = report["observations"]
    assert isinstance(observations, list)
    assert [o["verdict"] for o in observations] == ["unknown"] * 3 + ["pass"]
    assert len(peer.requests) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("peer", ["denied"], indirect=True)
async def test_blanket_rejection_is_not_origin_validation_proof(peer: ConformancePeer) -> None:
    report = await run_conformance_probe(_url(peer), 2)
    observations = report["observations"]
    assert isinstance(observations, list)
    assert [o["verdict"] for o in observations] == ["unknown"] * 4
    assert len(peer.requests) == 1


@pytest.mark.anyio
async def test_t9_never_sends_origin_to_non_loopback_url(
    peer: ConformancePeer, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def local_address(
        *args: object, **kwargs: object
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", peer.server_port))]

    monkeypatch.setattr("mcp_audit.conformance_probe.anyio.getaddrinfo", local_address)
    report = await run_conformance_probe(f"http://remote.example.test:{peer.server_port}/mcp", 2)
    observations = report["observations"]
    assert isinstance(observations, list)
    assert observations[-1]["verdict"] == "not_run"
    assert observations[-1]["reason"] == "loopback_only"
    assert len(peer.requests) == 4
    assert all("origin" not in headers for headers, _ in peer.requests)


@pytest.mark.anyio
async def test_localhost_cannot_resolve_outside_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    async def bad_address(
        *args: object, **kwargs: object
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))]

    async def forbidden_send(*args: object, **kwargs: object) -> None:
        raise AssertionError("non-loopback localhost resolution must not be contacted")

    monkeypatch.setattr("mcp_audit.conformance_probe.anyio.getaddrinfo", bad_address)
    monkeypatch.setattr("mcp_audit.conformance_probe._send", forbidden_send)
    report = await run_conformance_probe("http://localhost/mcp", 2)
    assert report["control_status"] is None


@pytest.mark.anyio
async def test_connection_failure_is_unknown_without_echoing_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("private-fixture-marker")

    monkeypatch.setattr("mcp_audit.conformance_probe._request_sync", unavailable)
    report = await run_conformance_probe("http://127.0.0.1:1/mcp", 0.1)
    assert report["control_status"] is None
    assert "private-fixture-marker" not in json.dumps(report)


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--help"],
        ["--url", "http://127.0.0.1/mcp"],
        ["--conformance-probe"],
        ["--conformance-probe", "session-resume", "list"],
    ],
)
def test_lab_never_probes_without_explicit_flag_and_url_or_alongside_topic(
    args: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def forbidden_probe(*args: object, **kwargs: object) -> None:
        raise AssertionError("unexpected negative probe")

    monkeypatch.setattr("mcp_audit.conformance_probe.run_conformance_probe", forbidden_probe)
    result = CliRunner().invoke(main, ["lab", *args])
    assert result.exit_code == (0 if args in ([], ["--help"]) else 2), result.output


@pytest.mark.parametrize(
    "url",
    [
        "file:///mcp",
        "http://user:synthetic@127.0.0.1/mcp",
        "http://127.0.0.1/mcp?synthetic=marker",
        "http://127.0.0.1/mcp#marker",
    ],
)
def test_credential_bearing_and_non_http_targets_are_rejected_before_requests(url: str) -> None:
    result = CliRunner().invoke(main, ["lab", "--conformance-probe", "--url", url])
    assert result.exit_code == 2
    assert url not in result.output
