"""Bounded, credential-free negative probes; never used by check or scan."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
from functools import partial
from urllib.parse import urlsplit

import anyio

from mcp_audit.probe import _json_object, _post_url, _request_sync, _Response

PROTOCOL_VERSION = "2026-07-28"
BAD_ORIGIN = "https://mcpaudit-conformance.invalid"


def _payload(method: str = "server/discover", **params: str) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                **params,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientInfo": {"name": "MCPAudit", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
    ).encode()


def _headers(method: str = "server/discover") -> dict[str, str]:
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }


def _error_code(response: _Response) -> int | None:
    if response.oversized or response.streamed:
        return None
    raw = _json_object(response.body)
    if raw is None or raw.get("jsonrpc") != "2.0" or type(raw.get("id")) is not int or raw["id"] != 1:
        return None
    error = raw.get("error")
    if "result" in raw or not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if type(code) is int and isinstance(error.get("message"), str) else None


def _modern_control(response: _Response | None) -> bool:
    if response is None or response.status != 200 or response.oversized or response.streamed:
        return False
    raw = _json_object(response.body)
    if raw is None or raw.get("jsonrpc") != "2.0" or type(raw.get("id")) is not int or raw["id"] != 1:
        return False
    result = raw.get("result")
    return (
        "error" not in raw
        and isinstance(result, dict)
        and isinstance(result.get("supportedVersions"), list)
        and PROTOCOL_VERSION in result["supportedVersions"]
    )


def _result(probe: str, variant: str, response: _Response | None) -> dict[str, object]:
    status = response.status if response is not None else None
    code = _error_code(response) if response is not None else None
    verdict = "unknown"
    reason = "request_unavailable"
    if response is not None:
        if (probe == "T7" and status == 400 and code == -32020) or (probe == "T9" and status == 403):
            verdict, reason = "pass", "expected_rejection"
        elif status is not None and 200 <= status < 300:
            verdict, reason = "fail", "negative_request_accepted"
        else:
            reason = "unexpected_response"
    return {
        "probe": probe,
        "variant": variant,
        "verdict": verdict,
        "reason": reason,
        "status": status,
        "error_code": code,
    }


async def _send(
    url: str, address: str, timeout: float, headers: dict[str, str], body: bytes
) -> _Response | None:
    try:
        with anyio.fail_after(timeout):
            return await anyio.to_thread.run_sync(
                partial(
                    _request_sync, url, "POST", address, timeout, request_headers=headers, request_body=body
                ),
                abandon_on_cancel=True,
            )
    except (OSError, TimeoutError, http.client.HTTPException):
        # Fixed unavailable evidence: exception text may contain endpoint or peer data.
        return None


async def run_conformance_probe(url: str, timeout: float) -> dict[str, object]:
    """Use one pinned address, a positive control, three T7 variants and loopback T9."""
    if not 0.1 <= timeout <= 30:
        raise ValueError("invalid request deadline")
    _post_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname
    assert host is not None
    try:
        literal_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        literal_loopback = False
    loopback = host == "localhost" or literal_loopback
    address: str | None = None
    try:
        with anyio.fail_after(timeout):
            addresses = await anyio.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
            )
        if addresses and (
            not loopback or all(ipaddress.ip_address(item[4][0]).is_loopback for item in addresses)
        ):
            address = addresses[0][4][0]
    except (OSError, TimeoutError):
        address = None

    control = await _send(url, address, timeout, _headers(), _payload()) if address is not None else None
    modern = _modern_control(control)
    observations: list[dict[str, object]] = []
    variants = (
        ("protocol_version", "MCP-Protocol-Version", "2025-11-25", "server/discover", _payload()),
        ("method", "Mcp-Method", "ping", "server/discover", _payload()),
        (
            "name",
            "Mcp-Name",
            "urn:mcpaudit:header-mismatch",
            "resources/read",
            _payload("resources/read", uri="urn:mcpaudit:conformance-probe"),
        ),
    )
    for variant, header, value, method, body in variants:
        if modern and address is not None:
            headers = _headers(method)
            headers[header] = value
            response = await _send(url, address, timeout, headers, body)
            observations.append(_result("T7", variant, response))
        else:
            observations.append(
                {
                    "probe": "T7",
                    "variant": variant,
                    "verdict": "unknown",
                    "reason": "modern_control_unavailable",
                    "status": None,
                    "error_code": None,
                }
            )

    if loopback and control is not None and control.status != 403 and address is not None:
        headers = _headers()
        headers["Origin"] = BAD_ORIGIN
        observations.append(_result("T9", "origin", await _send(url, address, timeout, headers, _payload())))
    else:
        observations.append(
            {
                "probe": "T9",
                "variant": "origin",
                "verdict": "not_run" if not loopback else "unknown",
                "reason": "loopback_only" if not loopback else "origin_control_unavailable",
                "status": None,
                "error_code": None,
            }
        )
    return {
        "contract": "mcpaudit.conformance-probe.v1",
        "protocol_version": PROTOCOL_VERSION,
        "control_status": control.status if control is not None else None,
        "modern_control": modern,
        "observations": observations,
        "claim_ceiling": "Bounded negative responses only; no general conformance or security certification.",
    }
