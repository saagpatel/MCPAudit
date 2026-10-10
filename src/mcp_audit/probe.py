"""Credential-free discovery on connected targets; public, pinned metadata GETs only."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from functools import partial
from typing import Literal
from urllib.parse import urlsplit

import anyio

from mcp_audit.authorization_posture_models import (
    MAX_AUTHORIZATION_SERVERS,
    MAX_FETCHES,
    _expected_authorization_metadata_url,
    _expected_resource_metadata_url,
    _origin,
    _require_https_url,
)
from mcp_audit.models import (
    AuthorizationFetch,
    AuthorizationFinding,
    AuthorizationProbeObservation,
)
from mcp_audit.redaction import redact_text
from mcp_audit.taxonomy import AUTHORIZATION_FINDINGS

MAX_BODY_BYTES = 65_536
MAX_CHALLENGE_FIELD_CHARS = 8_192
MAX_CHALLENGE_PARAMS = 32
MAX_BEARER_CHALLENGES = 8
_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_TCHAR = frozenset(_ALNUM + "!#$%&'*+-.^_`|~")
_TOKEN68 = frozenset(_ALNUM + "-._~+/")
_OWS = frozenset(" \t")
_EQUALS = frozenset("=")


@dataclass
class _Response:
    status: int
    challenges: list[str]
    session_id_present: bool
    body: bytes
    oversized: bool
    streamed: bool = False


class _Cursor:
    """Single-pass reader over a challenge list; backtracking is bounded to one element."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def take(self, allowed: frozenset[str]) -> str:
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] in allowed:
            self.pos += 1
        return self.text[start : self.pos]

    def ows(self) -> bool:
        return bool(self.take(_OWS))

    def element_end(self) -> bool:
        self.ows()
        return self.peek() in {"", ","}

    def quoted(self) -> str | None:
        """RFC 9110 quoted-string; each quoted-pair is decoded exactly once."""
        self.pos += 1
        decoded: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == '"':
                self.pos += 1
                return "".join(decoded)
            if char == "\\":
                escaped = self.text[self.pos + 1 : self.pos + 2]
                if not escaped or not (
                    escaped == "\t" or " " <= escaped <= "~" or "\x80" <= escaped <= "\xff"
                ):
                    return None
                decoded.append(escaped)
                self.pos += 2
                continue
            # qdtext: HTAB / SP / VCHAR except DQUOTE and backslash / obs-text.
            if not (char == "\t" or " " <= char <= "~" or "\x80" <= char <= "\xff"):
                return None
            decoded.append(char)
            self.pos += 1
        return None

    def param_value(self) -> str | None:
        """After an auth-param name: BWS "=" BWS ( token / quoted-string ), ending the element."""
        if self.peek() != "=":
            return None
        self.pos += 1
        self.ows()
        value = self.quoted() if self.peek() == '"' else self.take(_TCHAR) or None
        return value if value is not None and self.element_end() else None


def _challenges(headers: list[str]) -> tuple[list[dict[str, str]], bool]:
    """Parse RFC 9110 challenges, keeping Bearer parameters; fail closed on any doubt.

    The result is complete only when every field value parsed unambiguously and at most one
    ``resource_metadata`` appeared, inside a Bearer challenge. Anything else (several field
    lines, empty list elements, unattributable or duplicate parameters, malformed tokens or
    quoted strings, truncation, or a challenge or parameter cap) is incomplete, so no caller
    may treat a missing ``resource_metadata`` as an omitted advertisement.
    """
    challenges: list[dict[str, str]] = []
    if not headers:
        return challenges, False
    # Clients attribute parameters across repeated field lines inconsistently.
    incomplete = len(headers) > 1 or any(len(header) > MAX_CHALLENGE_FIELD_CHARS for header in headers)
    cursor = _Cursor(", ".join(header[:MAX_CHALLENGE_FIELD_CHARS] for header in headers))
    current: dict[str, str] | None = None  # The open Bearer challenge, if any.
    accepts_params = False  # The open challenge began with an auth-param.
    metadata_seen = 0

    def store(name: str, value: str) -> None:
        nonlocal incomplete, metadata_seen
        key = name.lower()
        if key == "resource_metadata":
            metadata_seen += 1
            incomplete |= metadata_seen > 1 or current is None
        if not accepts_params:
            incomplete = True  # No challenge owns this parameter.
        elif current is not None:
            if key in current or len(current) >= MAX_CHALLENGE_PARAMS:
                incomplete = True
            else:
                current[key] = value

    while True:
        cursor.ows()
        if cursor.peek() in {"", ","}:
            incomplete = True  # Empty field value or list element.
        else:
            name = cursor.take(_TCHAR)
            spaced = cursor.ows()
            if not name:
                return challenges, True
            if cursor.peek() == "=":
                # An auth-param continuing the open challenge.
                value = cursor.param_value()
                if value is None:
                    return challenges, True
                store(name, value)
            else:
                # A new challenge: scheme [ 1*SP ( token68 / auth-param ) ].
                current = {} if name.lower() == "bearer" else None
                if current is not None and len(challenges) < MAX_BEARER_CHALLENGES:
                    challenges.append(current)
                elif current is not None:
                    incomplete = True  # Parsed, but not retained as evidence.
                # Only "scheme SP auth-param" opens a parameter list; a bare scheme or a
                # token68 cannot own a later parameter.
                accepts_params = False
                if not cursor.element_end():
                    if not spaced:
                        return challenges, True
                    start = cursor.pos
                    param = cursor.take(_TCHAR)
                    cursor.ows()
                    value = cursor.param_value() if param else None
                    if value is not None:
                        accepts_params = True
                        store(param, value)
                    else:
                        cursor.pos = start
                        if not cursor.take(_TOKEN68):
                            return challenges, True
                        cursor.take(_EQUALS)
                        if not cursor.element_end():
                            return challenges, True
                        # RFC 6750 Bearer uses auth-params only; "scope=" may be a truncated one.
                        incomplete |= current is not None
        if not cursor.peek():
            return challenges, incomplete
        cursor.pos += 1  # The element separator.


def _json_object(raw: bytes) -> dict[str, object] | None:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value: object = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _post_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        len(url) > 2_048
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in url
        or any(ord(char) < 33 for char in url)
    ):
        raise ValueError("unsafe endpoint URL")
    _ = parsed.port


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        self.tls_context = ssl.create_default_context()
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(host, port, timeout=timeout, context=self.tls_context)
        self.address = address
        self.request_timeout = timeout

    def connect(self) -> None:
        started = time.monotonic()
        sock = _pinned_socket(self.address, self.port, self.request_timeout)
        try:
            remaining = self.request_timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("TLS deadline")
            sock.settimeout(remaining)
            self.sock = self.tls_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _pinned_socket(address: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((address, port))
        return sock
    except BaseException:
        sock.close()
        raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.address = address
        self.request_timeout = timeout

    def connect(self) -> None:
        self.sock = _pinned_socket(self.address, self.port, self.request_timeout)


def _request_sync(url: str, method: str, address: str, timeout: float) -> _Response:
    started = time.monotonic()
    parsed = urlsplit(url)
    host = parsed.hostname
    assert host is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection = (
        _PinnedHTTPSConnection(host, port, address, timeout)
        if parsed.scheme == "https"
        else _PinnedHTTPConnection(host, port, address, timeout)
    )
    headers = {"Accept": "application/json"}
    body: bytes | None = None
    if method == "POST":
        headers.update(
            {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",
            }
        )
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "MCPAudit", "version": "1"},
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        ).encode()
    timer: threading.Timer | None = None
    try:
        connection.connect()
        sock = connection.sock
        assert sock is not None

        def expire() -> None:
            # A peer that drips bytes must not outlive the request's wall-clock budget.
            # Shutdown can race normal connection closure.
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)

        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("request deadline")
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        connection.request(method, parsed.path or "/", body=body, headers=headers)
        response = connection.getresponse()
        # http.client does not decompress, follow redirects, use proxies, or retain cookies.
        streamed = response.getheader("Content-Type", "").split(";", 1)[0].lower() == "text/event-stream"
        # An open SSE stream is not a bounded JSON document; close after the headers.
        data = b"" if streamed else response.read(MAX_BODY_BYTES + 1)
        return _Response(
            response.status,
            [value for key, value in response.getheaders() if key.lower() == "www-authenticate"],
            response.getheader("Mcp-Session-Id") is not None,
            data[:MAX_BODY_BYTES],
            len(data) > MAX_BODY_BYTES,
            streamed,
        )
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


async def _request(url: str, method: Literal["POST", "GET"], timeout: float) -> _Response:
    if method == "GET":
        _require_https_url(url, query_allowed=False)
    else:
        _post_url(url)
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = await anyio.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("DNS returned no addresses")
    if method == "GET":
        for item in addresses:
            address = ipaddress.ip_address(item[4][0])
            if not address.is_global or address.is_multicast or address.is_reserved:
                raise ValueError("metadata DNS includes a non-public address")
    # Only one resolved address is used, including for the POST: no automatic retry.
    remaining = min(timeout, anyio.current_effective_deadline() - anyio.current_time())
    if remaining <= 0:
        raise TimeoutError("request deadline")
    return await anyio.to_thread.run_sync(
        partial(_request_sync, url, method, addresses[0][4][0], remaining), abandon_on_cancel=True
    )


class _Metadata:
    def __init__(self, observation: AuthorizationProbeObservation, timeout: float) -> None:
        self.observation = observation
        self.timeout = timeout

    async def fetch(self, url: str) -> dict[str, object] | None:
        if len(self.observation.metadata_fetches) >= MAX_FETCHES:
            self.observation.warnings.append("metadata_fetch_limit")
            return None
        record = AuthorizationFetch(url=redact_text(url), reason="unavailable")
        self.observation.metadata_fetches.append(record)
        try:
            response = await _request(url, "GET", self.timeout)
        except (OSError, ValueError, http.client.HTTPException):
            record.reason = "blocked_or_unavailable"
            return None
        record.status = response.status
        record.body_bytes = len(response.body)
        if response.oversized:
            record.reason = "body_limit"
            return None
        if response.status != 200:
            record.reason = "http_status"
            return None
        document = _json_object(response.body)
        record.reason = "json_object" if document is not None else "invalid_json"
        return document


def _finding(rule: str, target: str) -> AuthorizationFinding:
    metadata = AUTHORIZATION_FINDINGS[rule]
    return AuthorizationFinding(
        rule_id=rule,
        title=metadata.title,
        summary=metadata.description,
        severity="high"
        if metadata.severity == "high"
        else "medium"
        if metadata.severity == "medium"
        else "low",
        remediation=metadata.remediation,
        target_name=target,
    )


async def probe_authorization(
    url: str,
    *,
    timeout: float = 10.0,
    observation: AuthorizationProbeObservation | None = None,
    findings: list[AuthorizationFinding] | None = None,
) -> tuple[AuthorizationProbeObservation, list[AuthorizationFinding]]:
    """No config headers accepted; call only after the connected-scan eligibility gate."""
    if observation is None:
        observation = AuthorizationProbeObservation()
    if findings is None:
        findings = []
    try:
        if urlsplit(url).scheme == "http":
            findings.append(_finding("MCPAUTH012", "MCP endpoint"))
        with anyio.fail_after(timeout):
            response = await _request(url, "POST", timeout)
            observation.status = response.status
            observation.session_id_present = response.session_id_present
            challenges, challenge_incomplete = _challenges(response.challenges)
            if challenge_incomplete:
                observation.warnings.append("challenge_parse_incomplete")
            observation.www_authenticate = [
                {
                    key: redact_text(value)
                    if key in {"resource_metadata", "scope", "error"}
                    else "<redacted>"
                    for key, value in challenge.items()
                }
                for challenge in challenges
            ]
            if response.oversized:
                observation.warnings.append("probe_body_limit")
            elif response.streamed:
                observation.warnings.append("probe_stream_not_read")
            else:
                payload = _json_object(response.body)
                error = payload.get("error") if payload else None
                code = error.get("code") if isinstance(error, dict) else None
                if type(code) is int:
                    observation.jsonrpc_error_code = code
            if response.status == 401 and not challenge_incomplete:
                await _review_metadata(url, challenges, observation, findings, timeout)
    except (OSError, ValueError, http.client.HTTPException, TimeoutError):
        observation.warnings.append("probe_blocked_or_unavailable")
    return observation, findings


async def _review_metadata(
    url: str,
    challenges: list[dict[str, str]],
    observation: AuthorizationProbeObservation,
    findings: list[AuthorizationFinding],
    timeout: float,
) -> None:
    fetcher = _Metadata(observation, timeout)
    locations = [item["resource_metadata"] for item in challenges if "resource_metadata" in item]
    if not any(item.get("scope") for item in challenges):
        findings.append(_finding("MCPAUTH002", "WWW-Authenticate scope"))
    if locations:
        if not all(locations):
            observation.warnings.append("challenge_metadata_ambiguous")
            return
        for location in locations:
            if urlsplit(location).scheme != "https":
                findings.append(_finding("MCPAUTH012", "protected-resource metadata endpoint"))
        # Match the producer contract: a challenge may not widen the resource authority.
        locations = list(dict.fromkeys(locations))
        if len(locations) != 1 or _origin(locations[0]) != _origin(url):
            observation.warnings.append("challenge_metadata_outside_resource_authority")
            return
    else:
        locations = [
            discovered_location
            for discovery in (
                ["well-known-path", "well-known-root"]
                if urlsplit(url).path.strip("/")
                else ["well-known-root"]
            )
            if (discovered_location := _expected_resource_metadata_url(url, discovery)) is not None
        ]
    resource: dict[str, object] | None = None
    for location in locations:
        resource = await fetcher.fetch(location)
        if resource is not None:
            break
    if resource is None:
        # An unavailable or blocked fetch is not proof that metadata is missing.
        if observation.metadata_fetches and all(
            item.status in {404, 410} for item in observation.metadata_fetches
        ):
            findings.append(_finding("MCPAUTH001", "protected-resource metadata"))
        else:
            observation.warnings.append("resource_metadata_unavailable")
        return
    if not isinstance(resource.get("resource"), str):
        observation.warnings.append("resource_metadata_invalid")
        return
    if resource["resource"] != url:
        findings.append(_finding("MCPAUTH003", "protected-resource resource"))
        return
    issuers = resource.get("authorization_servers")
    if (
        not isinstance(issuers, list)
        or not issuers
        or len(issuers) > MAX_AUTHORIZATION_SERVERS
        or any(not isinstance(item, str) for item in issuers)
    ):
        observation.warnings.append("authorization_servers_invalid")
        return
    for issuer in dict.fromkeys(issuers):
        if not isinstance(issuer, str):
            continue
        try:
            _require_https_url(issuer, query_allowed=False)
        except ValueError:
            if urlsplit(issuer).scheme == "http":
                findings.append(_finding("MCPAUTH012", "authorization-server issuer"))
            observation.warnings.append("authorization_server_url_blocked")
            continue
        discovery_methods = (
            ["rfc8414-path-insertion", "openid-connect-path-insertion", "openid-connect-path-append"]
            if urlsplit(issuer).path.strip("/")
            else ["rfc8414", "openid-connect"]
        )
        metadata: dict[str, object] | None = None
        for discovery in discovery_methods:
            metadata = await fetcher.fetch(_expected_authorization_metadata_url(issuer, discovery))
            if metadata is not None:
                break
        if metadata is None:
            observation.warnings.append("authorization_metadata_unavailable")
            continue
        if not isinstance(metadata.get("issuer"), str):
            observation.warnings.append("authorization_metadata_invalid")
            continue
        if metadata["issuer"] != issuer:
            findings.append(_finding("MCPAUTH004", "authorization-server issuer"))
            continue
        endpoints = ("authorization_endpoint", "token_endpoint", "registration_endpoint")
        for endpoint in endpoints:
            value = metadata.get(endpoint)
            if isinstance(value, str) and urlsplit(value).scheme != "https":
                findings.append(_finding("MCPAUTH012", endpoint))
        methods = metadata.get("code_challenge_methods_supported")
        if not isinstance(methods, list) or "S256" not in methods:
            findings.append(_finding("MCPAUTH005", "authorization-server PKCE"))
        if (
            metadata.get("registration_endpoint")
            and metadata.get("client_id_metadata_document_supported") is not True
        ):
            findings.append(_finding("MCPAUTH006", "authorization-server registration advertisement"))
        if metadata.get("authorization_response_iss_parameter_supported") is not True:
            findings.append(_finding("MCPAUTH007", "authorization-server RFC 9207 advertisement"))
