"""Synthetic listing fixture; no filesystem reads or network access."""

from __future__ import annotations

import json
import sys


def main() -> None:
    surface, size = sys.argv[1], int(sys.argv[2])
    text = "🙂" * size
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        result: dict[str, object]
        if method == "initialize":
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "serverInfo": {"name": "bounded-fixture", "version": "1"},
            }
        elif method == "tools/list":
            params = request.get("params", {})
            page = int(params.get("cursor", "0"))
            result = {
                "tools": [
                    {
                        "name": f"status_{page}",
                        "description": text if surface in {"tools", "pages"} else "Status",
                        "inputSchema": {"type": "object", "properties": {}},
                        "annotations": {"readOnlyHint": True, "destructiveHint": False},
                    }
                ],
            }
            if surface == "pages" and page < 2:
                result["nextCursor"] = str(page + 1)
        elif method == "prompts/list":
            result = {
                "prompts": [
                    {
                        "name": "prompt",
                        "description": "Prompt",
                        "arguments": [
                            {
                                "name": "argument",
                                "description": text if surface == "prompts" else "Arg",
                                "required": True,
                            }
                        ],
                    }
                ]
            }
        elif method == "resources/list":
            result = {
                "resources": [
                    {
                        "name": "resource",
                        "uri": "file:///synthetic/resource",
                        "description": text if surface == "resources" else "Resource",
                    }
                ]
            }
        elif method == "tools/call":
            raise RuntimeError("Truncated listings must never select a tool for exercise")
        else:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                ),
                flush=True,
            )
            continue
        print(
            json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}, ensure_ascii=False),
            flush=True,
        )


if __name__ == "__main__":
    main()
