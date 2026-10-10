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
from io import BytesIO, StringIO
from typing import Literal, cast
from unittest.mock import Mock

import anyio
import pytest
from rich.console import Console

from mcp_audit import probe
from mcp_audit.connector import ServerConnector, _ServerCapabilities
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.finding_display import finding_views
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    AuthorizationFinding,
    AuthorizationProbeObservation,
    ServerAudit,
    ServerConfig,
    TransportType,
)
from mcp_audit.sarif import SarifGenerator
from mcp_audit.terminal_summary import render_summary
from tests.conftest import make_server_config, make_tool

RESOURCE = "https://mcp.fixture.test/mcp"
ISSUER = "https://auth.fixture.test/tenant"
PRM_PATH = "/.well-known/oauth-protected-resource/mcp"
AS_PATH = "/.well-known/oauth-authorization-server/tenant"
real_request = probe._request


@dataclass
class Peer:
    routes: dict[str, tuple[int, dict[str, str | list[str]], bytes]] = field(default_factory=dict)
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
                for line in value if isinstance(value, list) else [value]:
                    self.send_header(key, line)
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
                header_lines = "".join(
                    f"{key}: {line}\r\n"
                    for key, value in response_headers.items()
                    for line in (value if isinstance(value, list) else [value])
                )
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
@pytest.mark.parametrize("spacing", ["scope", "resource_metadata", "both"])
async def test_spaced_auth_parameters_with_mixed_schemes(peer: Peer, spacing: str) -> None:
    ready(peer)
    resource_equals = " = " if spacing in {"resource_metadata", "both"} else "="
    scope_equals = " = " if spacing in {"scope", "both"} else "="
    peer.routes["/mcp"] = (
        401,
        {
            "WWW-Authenticate": (
                'Basic realm="basic", Bearer '
                f'resource_metadata{resource_equals}"https://mcp.fixture.test/advertised", '
                f'scope{scope_equals}"read", Basic realm="other", scope = "ignored"'
            )
        },
        b"{}",
    )
    peer.routes["/advertised"] = peer.routes[PRM_PATH]
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings
    assert observation.www_authenticate == [
        {"resource_metadata": "https://mcp.fixture.test/advertised", "scope": "read"}
    ]
    assert [request[1] for request in peer.requests] == ["/mcp", "/advertised", AS_PATH]


ADVERTISED = 'resource_metadata="https://mcp.fixture.test/bad-prm"'


@pytest.mark.anyio
@pytest.mark.parametrize(
    "challenge_form",
    ["plain", "quoted_pairs", "quoted_comma_decoy", "mixed_schemes", "mixed_case_spaced"],
)
@pytest.mark.parametrize("rule", ["MCPAUTH003", "MCPAUTH004"])
async def test_advertised_metadata_not_replaced_by_clean_well_known(
    peer: Peer, challenge_form: str, rule: str
) -> None:
    ready(peer)  # Keep clean well-known metadata available to expose an incorrect fallback.
    forms = {
        "plain": f'Bearer {ADVERTISED}, scope="read"',
        # Valid quoted-pairs are decoded once and keep the challenge complete.
        "quoted_pairs": f'Bearer realm="a\\"b\\\\c\\,d", {ADVERTISED}, scope="read"',
        "quoted_comma_decoy": (
            'Bearer realm="x, resource_metadata=\\"https://mcp.fixture.test/decoy\\"", '
            f'{ADVERTISED}, scope="read"'
        ),
        "mixed_schemes": f'Negotiate abc+/==, Basic realm="b", Bearer {ADVERTISED}, scope="read"',
        "mixed_case_spaced": 'bearer Resource_Metadata = "https://mcp.fixture.test/bad-prm" , scope=read',
    }
    peer.routes["/mcp"] = (401, {"WWW-Authenticate": forms[challenge_form]}, b"{}")
    peer.document(
        "/bad-prm",
        {
            "resource": "https://mcp.fixture.test/other" if rule == "MCPAUTH003" else RESOURCE,
            "authorization_servers": [ISSUER],
        },
    )
    if rule == "MCPAUTH004":
        metadata = healthy_metadata()
        metadata["issuer"] = "https://other.fixture.test"
        peer.document(AS_PATH, metadata)
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert [finding.rule_id for finding in findings] == [rule]
    assert not observation.warnings
    assert observation.www_authenticate[-1]["resource_metadata"] == "https://mcp.fixture.test/bad-prm"
    expected = ["/mcp", "/bad-prm"] + ([AS_PATH] if rule == "MCPAUTH004" else [])
    assert [request[1] for request in peer.requests] == expected


def test_quoted_pairs_are_decoded_exactly_once() -> None:
    challenges, incomplete = probe._challenges([r'Bearer realm="a\"b\\c\\\"d", scope="r\ead"'])
    assert not incomplete
    assert challenges == [{"realm": 'a"b\\c\\"d', "scope": "read"}]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "challenge_form",
    [
        "metadata_line_before_bearer",
        "metadata_before_bearer_in_field",
        "metadata_in_basic_challenge",
        "metadata_after_token68",
        "duplicate_metadata",
        "conflicting_metadata",
        "metadata_in_two_bearer_challenges",
        "continuation_line",
        "empty_element",
        "empty_field_line",
        "trailing_comma",
        "duplicate_parameter",
        "bearer_token68",
        "bare_bearer_then_metadata",
    ],
)
async def test_unattributable_or_ambiguous_metadata_is_incomplete(peer: Peer, challenge_form: str) -> None:
    ready(peer)  # Clean well-known metadata stays available to expose an incorrect fallback.
    forms: dict[str, str | list[str]] = {
        "metadata_line_before_bearer": [ADVERTISED, 'Bearer scope="read"'],
        "metadata_before_bearer_in_field": f'{ADVERTISED}, Bearer scope="read"',
        "metadata_in_basic_challenge": f'Basic realm="b", {ADVERTISED}, Bearer scope="read"',
        "metadata_after_token68": f'Basic abc==, {ADVERTISED}, Bearer scope="read"',
        "duplicate_metadata": f'Bearer {ADVERTISED}, {ADVERTISED}, scope="read"',
        "conflicting_metadata": (
            f'Bearer {ADVERTISED}, resource_metadata="https://mcp.fixture.test/two", scope="read"'
        ),
        "metadata_in_two_bearer_challenges": f'Bearer {ADVERTISED}, scope="read", Bearer {ADVERTISED}',
        "continuation_line": ['Bearer realm="mcp"', f'{ADVERTISED}, scope="read"'],
        "empty_element": f'Bearer scope="read",, {ADVERTISED}',
        "empty_field_line": ['Bearer scope="read",', ADVERTISED],
        "trailing_comma": f'Bearer {ADVERTISED}, scope="read",',
        "duplicate_parameter": f'Bearer scope="read", {ADVERTISED}, scope="write"',
        "bearer_token68": f"Bearer scope=, {ADVERTISED}",
        "bare_bearer_then_metadata": f"Bearer, {ADVERTISED}",
    }
    peer.routes["/mcp"] = (401, {"WWW-Authenticate": forms[challenge_form]}, b"{}")
    peer.document("/bad-prm", {"resource": "https://mcp.fixture.test/other"})
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings  # Neither a clean fallback nor absent-scope guidance.
    assert observation.warnings == ["challenge_parse_incomplete"]
    assert not observation.metadata_fetches
    assert [request[1] for request in peer.requests] == ["/mcp"]


@pytest.mark.anyio
@pytest.mark.parametrize("extensions", [30, 31])
async def test_challenge_parameter_limit_cannot_hide_advertised_metadata(peer: Peer, extensions: int) -> None:
    ready(peer)
    parameters = ", ".join(f'p{i}="{i}"' for i in range(1, extensions + 1))
    peer.routes["/mcp"] = (
        401,
        {
            "WWW-Authenticate": (
                f'Bearer scope="read", {parameters}, resource_metadata="https://mcp.fixture.test/bad-prm"'
            )
        },
        b"{}",
    )
    peer.document("/bad-prm", {"resource": "https://mcp.fixture.test/other"})
    observation, findings = await probe.probe_authorization(RESOURCE)
    if extensions == 30:
        assert [finding.rule_id for finding in findings] == ["MCPAUTH003"]
        assert not observation.warnings
        assert [request[1] for request in peer.requests] == ["/mcp", "/bad-prm"]
    else:
        assert not findings
        assert observation.warnings == ["challenge_parse_incomplete"]
        assert not observation.metadata_fetches
        assert [request[1] for request in peer.requests] == ["/mcp"]
    assert len(observation.www_authenticate[0]) == 32


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [
        "header_limit",
        "malformed_parameter",
        "spaced_malformed_parameter",
        "malformed_bearer",
        "unclosed_quote",
    ],
)
async def test_incomplete_challenge_never_uses_clean_well_known(peer: Peer, failure: str) -> None:
    ready(peer)
    padding_prefix = 'Bearer scope="read", padding="'
    prefix = {
        # The retained 8,192 characters are valid: only the truncation flag can catch the lost URL.
        "header_limit": padding_prefix + "x" * (8_192 - len(padding_prefix) - 1) + '",',
        "malformed_parameter": 'Bearer scope="read", broken=,',
        "spaced_malformed_parameter": 'Bearer scope="read", broken =,',
        "malformed_bearer": "Bearer scope=,",
        "unclosed_quote": 'Bearer scope="read", Basic realm="unclosed,',
    }[failure]
    peer.routes["/mcp"] = (
        401,
        {"WWW-Authenticate": prefix + ' resource_metadata="https://mcp.fixture.test/bad-prm"'},
        b"{}",
    )
    peer.document("/bad-prm", {"resource": "https://mcp.fixture.test/other"})
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings
    assert observation.warnings == ["challenge_parse_incomplete"]
    assert not observation.metadata_fetches
    assert [request[1] for request in peer.requests] == ["/mcp"]


@pytest.mark.anyio
async def test_empty_metadata_advertisement_warns_without_fallback(peer: Peer) -> None:
    ready(peer)
    peer.routes["/mcp"] = (401, {"WWW-Authenticate": 'Bearer resource_metadata="", scope="read"'}, b"{}")
    observation, findings = await probe.probe_authorization(RESOURCE)
    assert not findings
    assert observation.warnings == ["challenge_metadata_ambiguous"]
    assert not observation.metadata_fetches
    assert [request[0] for request in peer.requests] == ["POST"]


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
    headers: dict[str, str | list[str]] = {}
    status, data = 200, b"{}"
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
@pytest.mark.parametrize("stalled_path", ["/mcp", PRM_PATH, AS_PATH])
@pytest.mark.parametrize("sdk_times_out", [False, True])
async def test_probe_stall_reserves_sdk_budget_and_retains_evidence(
    peer: Peer, monkeypatch: pytest.MonkeyPatch, stalled_path: str, sdk_times_out: bool
) -> None:
    ready(peer)
    completed_request = probe._request

    async def stalled_request(url: str, method: Literal["POST", "GET"], timeout: float) -> probe._Response:
        if url.endswith(stalled_path):
            await anyio.sleep_forever()
        return await completed_request(url, method, timeout)

    sdk_called = False

    async def enumerate_tools(self: ServerConnector, config: ServerConfig) -> _ServerCapabilities:
        nonlocal sdk_called
        sdk_called = True
        assert anyio.current_effective_deadline() > anyio.current_time()
        if sdk_times_out:
            await anyio.sleep_forever()
        await anyio.sleep(0.005)
        return _ServerCapabilities([make_tool(name="fixture-tool")], [], [])

    monkeypatch.setattr(probe, "_request", stalled_request)
    monkeypatch.setattr(ServerConnector, "_connect_http", enumerate_tools)
    config = make_server_config(transport=TransportType.HTTP, command=None, url=RESOURCE)
    audit = await ServerConnector(timeout=0.1).connect(config)
    assert sdk_called
    assert audit.connection_status == ("timeout" if sdk_times_out else "connected")
    if not sdk_times_out:
        assert [tool.name for tool in audit.tools] == ["fixture-tool"]
    observation = audit.authorization_probe
    assert observation is not None
    assert observation.warnings == ["probe_blocked_or_unavailable"]
    assert observation.status == (None if stalled_path == "/mcp" else 401)
    assert len(observation.metadata_fetches) == ["/mcp", PRM_PATH, AS_PATH].index(stalled_path)
    if observation.metadata_fetches:
        assert observation.jsonrpc_error_code == -32001
        assert observation.www_authenticate[0]["scope"] == "read"
        assert observation.metadata_fetches[-1].status is None
        assert observation.metadata_fetches[-1].reason == "unavailable"
    if stalled_path == AS_PATH:
        assert observation.metadata_fetches[0].status == 200
        assert observation.metadata_fetches[0].reason == "json_object"


@pytest.mark.anyio
async def test_outer_cancellation_retains_incremental_probe_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = AuthorizationProbeObservation()
    findings: list[AuthorizationFinding] = []
    metadata_started = anyio.Event()

    async def request(url: str, method: Literal["POST", "GET"], timeout: float) -> probe._Response:
        if method == "POST":
            return probe._Response(401, ['Bearer realm="mcp"'], False, b"{}", False)
        metadata_started.set()
        await anyio.sleep_forever()
        raise AssertionError("unreachable")

    async def run() -> None:
        await probe.probe_authorization(RESOURCE, observation=observation, findings=findings)

    monkeypatch.setattr(probe, "_request", request)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(run)
        await metadata_started.wait()
        tasks.cancel_scope.cancel()
    assert observation.status == 401
    assert observation.www_authenticate == [{"realm": "<redacted>"}]
    assert [finding.rule_id for finding in findings] == ["MCPAUTH002"]
    assert len(observation.metadata_fetches) == 1
    assert observation.metadata_fetches[0].status is None


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["unavailable", "incomplete_challenge", "metadata_unavailable", "none"])
async def test_probe_warnings_survive_successful_sdk_and_report_projections(
    peer: Peer, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    ready(peer)
    expected_reason = {
        "unavailable": "probe_blocked_or_unavailable",
        "incomplete_challenge": "challenge_parse_incomplete",
        "metadata_unavailable": "resource_metadata_unavailable",
    }.get(failure)
    if failure == "incomplete_challenge":
        peer.routes["/mcp"] = (401, {"WWW-Authenticate": 'Bearer scope="read", broken='}, b"{}")
    elif failure == "metadata_unavailable":
        peer.routes[PRM_PATH] = (503, {}, b"{}")
    elif failure == "unavailable":

        async def unavailable(url: str, method: Literal["POST", "GET"], timeout: float) -> probe._Response:
            raise OSError("synthetic unavailable probe")

        monkeypatch.setattr(probe, "_request", unavailable)

    async def enumerate_tools(self: ServerConnector, config: ServerConfig) -> _ServerCapabilities:
        return _ServerCapabilities([make_tool(name="fixture-tool")], [], [])

    monkeypatch.setattr(ServerConnector, "_connect_http", enumerate_tools)
    server = make_server_config(transport=TransportType.HTTP, command=None, url=RESOURCE)
    report = await run_scan(ScanOptions(config_only=True), servers=[server])
    audit = report.audits[0]
    assert audit.connection_status == "connected"
    assert report.servers_connected == 1
    assert [tool.name for tool in audit.tools] == ["fixture-tool"]
    assert audit.authorization_probe is not None
    warnings = [warning for warning in report.warnings if warning.code == "authorization_probe_incomplete"]
    if expected_reason is None:
        assert not audit.authorization_probe.warnings
        assert not warnings
        assert report.ensure_review_summary().grade is not None
        return
    assert audit.authorization_probe.warnings == [expected_reason]
    assert len(warnings) == 1
    warning = warnings[0]
    assert warning.servers == [server.name]
    assert expected_reason in warning.message
    assert report.ensure_review_summary().grade is None
    assert report.ux_summary.grade is None
    assert expected_reason in report.model_dump_json()
    html = HtmlReportGenerator().generate(report)
    assert warning.code in html and expected_reason in html
    terminal = StringIO()
    render_summary(Console(file=terminal, width=200, color_system=None), report)
    assert expected_reason in terminal.getvalue()
    assert "Preview" in terminal.getvalue()
    for profile in ("compatibility", "extended"):
        sarif = SarifGenerator().generate(report, profile=profile)
        notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        notification = next(
            item for item in notifications if item["descriptor"]["id"] == "MCP-AUTHORIZATION-PROBE-INCOMPLETE"
        )
        assert notification["level"] == "warning"
        assert notification["message"]["text"] == warning.message
        assert notification["properties"] == warning.model_dump()


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


def _adversarial_challenges() -> list[str | list[str]]:
    """Header shapes that all advertise one metadata URL; deterministic, no randomness."""
    url = "https://mcp.fixture.test/bad-prm"
    metadata = [
        f'resource_metadata="{url}"',
        f'Resource_Metadata = "{url}"',
        f'RESOURCE_METADATA\t=\t"{url}"',
        f"resource_metadata={url}",  # ":" and "/" are not token characters.
        f'resource_metadata="{url}\\"',  # The closing quote is escaped.
        'resource_metadata="https:\\/\\/mcp.fixture.test\\/bad-prm"',  # Valid quoted-pairs.
    ]
    neighbours = [
        'scope="read"',
        'realm="a, b"',
        'realm="a\\"b"',
        'realm="\\\\"',
        "error=invalid_token",
        'p = "v"',
        "",
        'realm="\x01"',
        'realm="a\\',
        "realm=",
        "=x",
        "p=a b",
    ]
    schemes = ["Bearer", "bearer", "BEARER", "Basic", "Negotiate abc==", "Bearer abc==", "DPoP", ""]
    shapes: list[str | list[str]] = []
    for item in metadata:
        for neighbour in neighbours:
            for scheme in schemes:
                head = f"{scheme} {item}".strip()
                shapes.append(f"{head}, {neighbour}")
                shapes.append(f"{scheme} {neighbour}, {item}".strip())
                shapes.append(f"{neighbour}, {head}")
                shapes.append([f"{scheme} {neighbour}".strip(), item])
                shapes.append([item, f"{scheme} {neighbour}".strip()])
        shapes.append(f"Bearer {item}," + ", ".join(f'p{i}="{i}"' for i in range(40)))
        shapes.append("Bearer " + ", ".join(f'p{i}="{i}"' for i in range(31)) + f", {item}")
        shapes.append(f'Basic realm="x", Bearer {item}, scope="read", Basic realm="y"')
        shapes.append(f"Bearer {item}, {item}")
        shapes.append(f"Bearer {item}, Bearer {item}")
        shapes.append(f"Bearer {item},")
        shapes.append(f", Bearer {item}")
        shapes.append(f"Bearer  {item}")
        shapes.append(f"Bearer{item}")
    return shapes


@pytest.mark.anyio
async def test_advertised_metadata_is_used_or_review_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Property: an advertisement is never replaced by a silent, clean well-known fallback."""
    gets: list[str] = []
    challenge: list[str] = []
    prm = json.dumps({"resource": "https://mcp.fixture.test/other"}).encode()
    clean = json.dumps({"resource": RESOURCE, "authorization_servers": [ISSUER]}).encode()

    async def respond(url: str, method: Literal["POST", "GET"], timeout: float) -> probe._Response:
        if method == "POST":
            return probe._Response(401, list(challenge), False, b"{}", False)
        gets.append(url)
        if url.endswith("/bad-prm"):
            return probe._Response(200, [], False, prm, False)
        if "/.well-known/oauth-protected-resource" in url:
            return probe._Response(200, [], False, clean, False)
        return probe._Response(200, [], False, json.dumps(healthy_metadata()).encode(), False)

    monkeypatch.setattr(probe, "_request", respond)
    shapes = _adversarial_challenges()
    assert len(shapes) > 2_500
    outcomes = {"used": 0, "incomplete": 0, "withheld": 0}
    for shape in shapes:
        challenge[:] = shape if isinstance(shape, list) else [shape]
        gets.clear()
        observation, findings = await probe.probe_authorization(RESOURCE)
        assert not any("/.well-known/oauth-protected-resource" in url for url in gets), shape
        if "challenge_parse_incomplete" in observation.warnings:
            outcomes["incomplete"] += 1
            assert not gets and not findings, shape
        elif gets:
            outcomes["used"] += 1
            assert gets == ["https://mcp.fixture.test/bad-prm"], shape
            assert "MCPAUTH003" in [finding.rule_id for finding in findings], shape
        else:
            # Only a well-formed advertisement that the binding checks refuse may skip a fetch.
            outcomes["withheld"] += 1
            assert observation.warnings == ["challenge_metadata_outside_resource_authority"], shape
    assert outcomes["used"] and outcomes["incomplete"]


@pytest.mark.parametrize(
    "header",
    [
        'Basic realm="x"',
        'Negotiate abc==, Basic realm="x"',
        'Bearer scope="read"',
        "Bearer",
        'Bearer realm="a\\"b"',
    ],
)
def test_complete_parse_without_advertisement_permits_well_known(header: str) -> None:
    challenges, incomplete = probe._challenges([header])
    assert not incomplete
    assert all("resource_metadata" not in challenge for challenge in challenges)


def test_bearer_challenge_cap_is_incomplete() -> None:
    challenges, incomplete = probe._challenges([", ".join(["Bearer"] * (probe.MAX_BEARER_CHALLENGES + 1))])
    assert incomplete
    assert len(challenges) == probe.MAX_BEARER_CHALLENGES


def test_probe_tls_context_refuses_legacy_protocols() -> None:
    import ssl

    from mcp_audit.probe import _PinnedHTTPSConnection

    connection = _PinnedHTTPSConnection("example.test", 443, "203.0.113.10", timeout=1)
    assert connection.tls_context.minimum_version == ssl.TLSVersion.TLSv1_2
