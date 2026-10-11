"""Disposable loopback peer for negative conformance acceptance tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

from tests.fixtures.protocol_server import ProtocolServer


class ConformanceServer(ThreadingHTTPServer):
    def __init__(self, mode: str) -> None:
        super().__init__(("127.0.0.1", 0), ConformanceHandler)
        self.peer = ConformancePeer(mode, self.server_port)


class ConformanceHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        server = cast(ConformanceServer, self.server)
        body: dict[str, object] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        headers = {key.lower(): value for key, value in self.headers.items()}
        status, data = server.peer.respond(headers, body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Mcp-Session-Id", "private-fixture-marker")
        self.send_header("Set-Cookie", "synthetic=private-fixture-marker")
        if status == 302:
            self.send_header("Location", "https://redirect.invalid/mcp")
        self.end_headers()
        self.wfile.write(data)


@dataclass
class ConformancePeer:
    mode: str
    server_port: int = 8765
    requests: list[tuple[dict[str, str], dict[str, object]]] = field(default_factory=list)

    def respond(self, headers: dict[str, str], body: dict[str, object]) -> tuple[int, bytes]:
        self.requests.append((headers, body))
        params = body.get("params")
        assert isinstance(params, dict)
        meta = params["_meta"]
        assert isinstance(meta, dict)
        mismatch = (
            headers["mcp-protocol-version"] != meta["io.modelcontextprotocol/protocolVersion"]
            or headers["mcp-method"] != body["method"]
            or ("uri" in params and headers.get("mcp-name") != params["uri"])
        )
        negative = mismatch or "origin" in headers
        status, code = 200, None
        if negative and self.mode != "accept":
            status, code = (400, -32020) if mismatch else (403, -32600)
            if self.mode == "wrong-error":
                status, code = 400, -32600
            elif self.mode == "auth":
                status, code = 401, -32600
            elif self.mode == "redirect":
                status, code = 302, -32600
        elif not negative and self.mode == "legacy":
            status, code = 404, -32601
        elif not negative and self.mode == "denied":
            status, code = 403, -32600
        response = (
            {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "private-fixture-marker"}}
            if code is not None
            else ProtocolServer("modern").respond(body)
        )
        data = json.dumps(response).encode()
        if negative and self.mode == "oversized":
            data = b"x" * 65_537
        return status, data
