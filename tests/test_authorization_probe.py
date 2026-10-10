"""Credential-free probe rules and network boundary, against program-owned HTTP peers."""

from __future__ import annotations

import json
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from typing import Literal, cast
from unittest.mock import Mock

import pytest

from mcp_audit import probe
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.finding_display import finding_views
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    AuthorizationProbeObservation,
    ServerAudit,
    ServerConfig,
    TransportType,
)
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

RESOURCE = "https://mcp.fixture.test/mcp"
ISSUER = "https://auth.fixture.test/tenant"
PRM_PATH = "/.well-known/oauth-protected-resource/mcp"
AS_PATH = "/.well-known/oauth-authorization-server/tenant"
real_request = probe._request


@dataclass
class Peer:
    routes: dict[str, tuple[int, dict[str, str], bytes]] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, str], bytes]] = field(default_factory=list)
    port: int = 0

    def document(self, path: str, document: dict[str, object]) -> None:
        self.routes[path] = (200, {"Content-Type": "application/json"}, json.dumps(document).encode())


@pytest.fixture(params=["wire", "http"])
def peer(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[Peer]:
    peer = Peer()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.respond()

        def do_GET(self) -> None:
            self.respond()

        def log_message(self, format: str, *args: object) -> None:
            return

        def respond(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            peer.requests.append((self.command, self.path, dict(self.headers), body))
            status, headers, data = peer.routes.get(self.path, (404, {}, b""))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    if request.param == "http":
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        peer.port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

    async def resolve(
        host: str, port: int, *, type: int
    ) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]]:
        assert host in {"mcp.fixture.test", "auth.fixture.test"}
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    def connect(connection: probe._PinnedHTTPSConnection) -> None:
        # The rule fixture uses plain local HTTP in place of TLS on the pinned public route.
        # Public-address validation and production request construction remain active.
        assert connection.address == "8.8.8.8"
        if request.param == "http":
            connection.sock = probe._pinned_socket("127.0.0.1", peer.port, connection.request_timeout)
        else:
            wire = bytearray()
            sock = Mock(spec=socket.socket)
            sock.sendall.side_effect = wire.extend

            def response(*args: object, **kwargs: object) -> BytesIO:
                raw_headers, _, body = bytes(wire).partition(b"\r\n\r\n")
                start, *lines = raw_headers.decode().split("\r\n")
                method, path, _ = start.split(" ")
                headers = dict(line.split(": ", 1) for line in lines)
                peer.requests.append((method, path, headers, body))
                status, response_headers, data = peer.routes.get(path, (404, {}, b""))
                header_lines = "".join(f"{key}: {value}\r\n" for key, value in response_headers.items())
                return BytesIO(
                    f"HTTP/1.1 {status} Fixture\r\n{header_lines}Content-Length: {len(data)}\r\n\r\n".encode()
                    + data
                )

            sock.makefile.side_effect = response
            connection.sock = cast(socket.socket, sock)

    monkeypatch.setattr(probe, "_request", real_request)
    monkeypatch.setattr("mcp_audit.probe.anyio.getaddrinfo", resolve)
    monkeypatch.setattr(probe._PinnedHTTPSConnection, "connect", connect)
    try:
        yield peer
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)


def ready(peer: Peer) -> None:
    peer.routes["/mcp"] = (
        401,
        {"WWW-Authenticate": f'Bearer resource_metadata="https://mcp.fixture.test{PRM_PATH}", scope="read"'},
        b'{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"withheld"}}',
    )
    peer.document(PRM_PATH, {"resource": RESOURCE, "authorization_servers": [ISSUER]})
    peer.document(AS_PATH, healthy_metadata())


def healthy_metadata() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": "https://auth.fixture.test/authorize",
        "token_endpoint": "https://auth.fixture.test/token",
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    "rule,field,value,severity",
    [
        ("MCPAUTH004", "issuer", "https://other.fixture.test", "high"),
        ("MCPAUTH005", "code_challenge_methods_supported", ["plain"], "medium"),
        ("MCPAUTH006", "client_id_metadata_document_supported", False, "low"),
        ("MCPAUTH007", "authorization_response_iss_parameter_supported", False, "low"),
        ("MCPAUTH012", "token_endpoint", "http://auth.fixture.test/token", "medium"),
    ],
)
async def test_authorization_metadata_rules(
    peer: Peer, rule: str, field: str, value: object, severity: str
) -> None:
    ready(peer)
    metadata = healthy_metadata()
    metadata[field] = value
    if rule == "MCPAUTH006":
        metadata["registration_endpoint"] = "https://auth.fixture.test/register"
    peer.document(AS_PATH, metadata)
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert [(item.rule_id, item.severity) for item in findings] == [(rule, severity)]
    assert observation.status == 401
    assert observation.jsonrpc_error_code == -32001
    assert [item.status for item in observation.metadata_fetches] == [200, 200]
    assert [request[0] for request in peer.requests] == ["POST", "GET", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("rule", ["MCPAUTH001", "MCPAUTH002", "MCPAUTH003"])
async def test_resource_metadata_rules(peer: Peer, rule: str) -> None:
    ready(peer)
    if rule == "MCPAUTH001":
        peer.routes.pop(PRM_PATH)
    elif rule == "MCPAUTH002":
        peer.routes["/mcp"] = (
            401,
            {"WWW-Authenticate": f'Bearer resource_metadata="https://mcp.fixture.test{PRM_PATH}"'},
            b"{}",
        )
    else:
        peer.document(
            PRM_PATH, {"resource": "https://mcp.fixture.test/other", "authorization_servers": [ISSUER]}
        )
    _, findings = await probe.probe_authorization(RESOURCE)
    assert [finding.rule_id for finding in findings] == [rule]
    if rule == "MCPAUTH003":
        assert [request[0] for request in peer.requests] == ["POST", "GET"]


@pytest.mark.anyio
async def test_clean_fixture_and_redacted_headers(peer: Peer) -> None:
    ready(peer)
    peer.routes["/mcp"] = (
        401,
        {
            "WWW-Authenticate": (
                f'Basic realm="withheld", Bearer resource_metadata="https://mcp.fixture.test{PRM_PATH}", '
                'scope="read write admin", realm="private-realm", api_key="synthetic-marker"'
            ),
            "Mcp-Session-Id": "private-session-marker",
            "Set-Cookie": "private-cookie-marker",
        },
        b"{}",
    )
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings  # Scopes need not be a subset of PRM scopes_supported.
    assert observation.session_id_present is True
    assert observation.www_authenticate[0]["scope"] == "read write admin"
    serialized = observation.model_dump_json()
    assert all(
        marker not in serialized
        for marker in ["synthetic-marker", "private-realm", "private-session-marker", "private-cookie-marker"]
    )
    method, path, headers, raw = peer.requests[0]
    assert (method, path) == ("POST", "/mcp")
    assert headers["Mcp-Method"] == "server/discover"
    assert headers["MCP-Protocol-Version"] == "2026-07-28"
    assert headers["Accept"] == "application/json, text/event-stream"
    assert json.loads(raw)["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    for _, _, headers, _ in peer.requests:
        assert not {key.lower() for key in headers} & {"authorization", "cookie", "mcp-session-id"}


@pytest.mark.anyio
@pytest.mark.parametrize("status", [200, 400, 403, 404, 302])
async def test_only_401_fetches_metadata_and_no_redirects(peer: Peer, status: int) -> None:
    ready(peer)
    _, headers, body = peer.routes["/mcp"]
    peer.routes["/mcp"] = (status, {**headers, "Location": "https://auth.fixture.test/redirect"}, body)
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert observation.status == status
    assert not observation.metadata_fetches
    assert not findings
    assert len(peer.requests) == 1


@pytest.mark.anyio
async def test_sse_probe_closes_after_headers(peer: Peer) -> None:
    peer.routes["/mcp"] = (200, {"Content-Type": "text/event-stream"}, b"data: withheld\n\n")
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert observation.status == 200
    assert observation.jsonrpc_error_code is None
    assert observation.warnings == ["probe_stream_not_read"]
    assert not findings


@pytest.mark.anyio
@pytest.mark.parametrize(
    "location,expected",
    [("http://mcp.fixture.test/prm", ["MCPAUTH012"]), ("https://other.fixture.test/prm", [])],
)
async def test_challenge_cannot_widen_resource_authority(
    peer: Peer, location: str, expected: list[str]
) -> None:
    peer.routes["/mcp"] = (
        401,
        {"WWW-Authenticate": f'Bearer resource_metadata="{location}", scope="read"'},
        b"{}",
    )
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert [finding.rule_id for finding in findings] == expected
    assert observation.warnings == ["challenge_metadata_outside_resource_authority"]
    assert len(peer.requests) == 1


def test_tls_verifies_original_host_on_pinned_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = probe._PinnedHTTPSConnection("metadata.fixture.test", 443, "8.8.8.8", 1)
    assert connection.tls_context.check_hostname
    assert connection.tls_context.verify_mode == ssl.CERT_REQUIRED
    sock = Mock(spec=socket.socket)
    pinned = Mock(return_value=sock)
    wrap = Mock(return_value=sock)
    monkeypatch.setattr(probe, "_pinned_socket", pinned)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    connection.connect()
    pinned.assert_called_once_with("8.8.8.8", 443, 1)
    wrap.assert_called_once_with(sock, server_hostname="metadata.fixture.test")
    connection.close()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["redirect", "large", "invalid", "duplicate", "unavailable"])
async def test_bad_metadata_is_unknown_not_missing(peer: Peer, mode: str) -> None:
    ready(peer)
    status, headers, data = 200, {}, b"{}"
    if mode == "redirect":
        status, headers = 302, {"Location": "https://auth.fixture.test/redirect"}
    elif mode == "large":
        data = b" " * (probe.MAX_BODY_BYTES + 1)
    elif mode == "invalid":
        data = b"not JSON"
    elif mode == "duplicate":
        data = b'{"resource":"one","resource":"two"}'
    else:
        status = 503
    peer.routes[PRM_PATH] = (status, headers, data)
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings
    assert observation.warnings
    assert len(peer.requests) == 2
    assert observation.metadata_fetches[0].body_bytes is not None
    assert observation.metadata_fetches[0].body_bytes <= probe.MAX_BODY_BYTES


@pytest.mark.anyio
async def test_well_known_and_oidc_fallback_order(peer: Peer) -> None:
    ready(peer)
    peer.routes["/mcp"] = (401, {"WWW-Authenticate": 'Bearer scope="read"'}, b"{}")
    prm = peer.routes.pop(PRM_PATH)
    peer.routes["/.well-known/oauth-protected-resource"] = prm
    metadata = peer.routes.pop(AS_PATH)
    peer.routes["/tenant/.well-known/openid-configuration"] = metadata
    _, findings = await probe.probe_authorization(RESOURCE)
    assert not findings
    assert [request[1] for request in peer.requests] == [
        "/mcp",
        PRM_PATH,
        "/.well-known/oauth-protected-resource",
        AS_PATH,
        "/.well-known/openid-configuration/tenant",
        "/tenant/.well-known/openid-configuration",
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "http://metadata.fixture.test/prm",
        "https://127.0.0.1/prm",
        "https://localhost/prm",
        "https://metadata.fixture.test/prm?token=synthetic",
        "https://user:synthetic@metadata.fixture.test/prm",
    ],
)
async def test_metadata_url_boundary_before_dns(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    async def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("blocked URL reached DNS")

    monkeypatch.setattr("mcp_audit.probe.anyio.getaddrinfo", forbidden)
    with pytest.raises(ValueError):
        await real_request(url, "GET", 1)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "ff02::1"]
)
async def test_all_dns_addresses_must_be_public(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    async def resolve(*args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", (address, 443))]

    monkeypatch.setattr("mcp_audit.probe.anyio.getaddrinfo", resolve)
    with pytest.raises(ValueError, match="non-public"):
        await real_request("https://metadata.fixture.test/prm", "GET", 1)


@pytest.mark.anyio
async def test_fetch_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    count = 0

    async def response(url: str, method: Literal["POST", "GET"], timeout: float) -> probe._Response:
        nonlocal count
        count += 1
        return probe._Response(404, [], False, b"", False)

    monkeypatch.setattr(probe, "_request", response)
    observation = AuthorizationProbeObservation()
    fetcher = probe._Metadata(observation, 1)
    for _ in range(33):
        await fetcher.fetch("https://metadata.fixture.test/prm")
    assert count == len(observation.metadata_fetches) == 32
    assert observation.warnings == ["metadata_fetch_limit"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "skip,project,connect,expected",
    [
        (True, False, False, 0),
        (False, True, False, 0),
        (True, True, True, 0),
        (False, True, True, 1),
        (False, False, False, 1),
    ],
)
async def test_scan_connection_gates_and_failed_sdk_retains_evidence(
    peer: Peer, monkeypatch: pytest.MonkeyPatch, skip: bool, project: bool, connect: bool, expected: int
) -> None:
    peer.routes["/mcp"] = (404, {}, b'{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}')

    async def unavailable(self: ServerConnector, config: ServerConfig) -> None:
        raise RuntimeError("synthetic SDK failure")

    monkeypatch.setattr(ServerConnector, "_connect_http", unavailable)
    server = make_server_config(transport=TransportType.HTTP, command=None, url=RESOURCE)
    server.headers_keys = ["Authorization", "Cookie", "X-Api-Key"]
    server.scope = "project" if project else "workstation"
    report = await run_scan(
        ScanOptions(config_only=True, skip_connect=skip, connect_project_configs=connect), servers=[server]
    )
    audit = report.audits[0]
    assert len(peer.requests) == expected
    if expected:
        assert audit.connection_status == "failed"
        assert audit.authorization_probe is not None
        assert audit.authorization_probe.jsonrpc_error_code == -32601
        assert not {key.lower() for key in peer.requests[0][2]} & {"authorization", "cookie", "x-api-key"}
    else:
        assert audit.authorization_probe is None
        assert "authorization_probe" not in audit.model_dump(mode="json")


@pytest.mark.anyio
async def test_findings_survive_report_projections(peer: Peer) -> None:
    ready(peer)
    metadata = healthy_metadata()
    metadata["issuer"] = "https://other.fixture.test"
    peer.document(AS_PATH, metadata)
    observation, findings = await probe.probe_authorization(RESOURCE)
    server = make_server_config(transport=TransportType.HTTP, command=None, url=RESOURCE)
    audit = ServerAudit(
        server=server,
        connection_status="failed",
        authorization_probe=observation,
        authorization_findings=findings,
    )
    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="synthetic",
        os_platform="test",
        audits=[audit],
        servers_discovered=1,
        servers_connected=0,
        servers_failed=1,
        total_tools=0,
        high_risk_servers=0,
        scan_duration_seconds=0.0,
    )
    assert any(view.rule_id == "MCPAUTH004" for view in finding_views(report))
    assert any(action.severity == "high" for action in report.ensure_review_summary().actions)
    assert "MCPAUTH004" in HtmlReportGenerator().generate(report)
    sarif = SarifGenerator().generate(report)
    assert any(
        result["ruleId"] == "MCPAUTH004" and result["level"] == "error"
        for result in sarif["runs"][0]["results"]
    )
