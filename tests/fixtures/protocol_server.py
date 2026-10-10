"""Synthetic protocol peer for stdio and mocked HTTP; no external operations."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field


@dataclass
class ProtocolServer:
    mode: str
    calls: int = 0
    methods: list[str] = field(default_factory=list)

    def respond(self, request: dict[str, object]) -> dict[str, object] | None:
        method = str(request.get("method"))
        self.methods.append(method)
        if "id" not in request:
            return None
        hints: dict[str, object] = {"ttlMs": 0, "cacheScope": "private"}
        result: dict[str, object] = {"resultType": "complete", **hints}
        capabilities: dict[str, object] = {
            "tools": {},
            "extensions": {"io.modelcontextprotocol/tasks": {}},
        }
        if self.mode == "logging":
            capabilities["logging"] = {}
        if method == "server/discover":
            if self.mode in {"legacy", "legacy-no-hints"}:
                return {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32601, "message": "Synthetic legacy peer"},
                }
            result.update(
                {
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": capabilities,
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {"name": "synthetic-protocol", "version": "1"}
                    },
                }
            )
        elif method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": capabilities,
                "serverInfo": {"name": "synthetic-protocol", "version": "1"},
            }
        elif method == "tools/list":
            names = ["status", "health"]
            if self.mode == "order" and self.calls:
                names.reverse()
            if self.mode == "change" and self.calls:
                names.append("ready")
            if self.mode == "scope-mismatch":
                params = request.get("params")
                if isinstance(params, dict) and params.get("cursor"):
                    names = ["health"]
                    result["cacheScope"] = "public"
                else:
                    names = ["status"]
                    result["nextCursor"] = "synthetic-page-2"
            result["tools"] = [
                {
                    "name": name,
                    "description": "Synthetic status.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": True, "destructiveHint": False},
                }
                for name in names
            ]
            if self.mode in {"no-hints", "legacy-no-hints"}:
                result.pop("ttlMs")
                result.pop("cacheScope")
            elif self.mode == "invalid-ttl":
                result["ttlMs"] = -1
            elif self.mode == "invalid-ttl-secret":
                result["ttlMs"] = "Bearer synthetic-validation-marker"
            elif self.mode == "missing-evidence":
                return {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32603, "message": "Synthetic unavailable listing"},
                }
        elif method == "prompts/list":
            result["prompts"] = []
        elif method == "resources/list":
            result["resources"] = []
        elif method == "tools/call":
            self.calls += 1
            result = {"resultType": "complete", "content": [{"type": "text", "text": "Synthetic OK"}]}
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def main() -> None:
    server = ProtocolServer(sys.argv[1])
    for line in sys.stdin:
        request: dict[str, object] = json.loads(line)
        response = server.respond(request)
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
