"""Disposable stdio canary surfaces; never accesses files, secrets, or networks.

Reproduces transient-listing laundering, advertised capability boundaries,
individual get failures, dynamic prompt text, and two-page listings.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def main() -> None:
    mode = sys.argv[1]
    calls = 0
    gets = 0
    listing_failed = False
    for line in sys.stdin:
        request: dict[str, Any] = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        params = request.get("params", {})
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": request["id"]}
        result: dict[str, Any]
        category = method.split("/")[0]
        if (
            (mode == f"launder_{category}" and method.endswith("/list") and calls == 3 and not listing_failed)
            or (
                mode == "get_failure"
                and method == "prompts/get"
                and params["name"] == "summary0"
                and calls == 3
            )
            or (mode == "initial_get_failure" and method == "prompts/get" and calls == 0)
        ):
            listing_failed = True
            response["error"] = {"code": -32603, "message": "synthetic transient failure"}
        elif mode == "tools_only" and category in {"prompts", "resources"}:
            response["error"] = {"code": -32601, "message": "unadvertised surface was probed"}
        else:
            changed = calls >= 3
            page = int(params.get("cursor", "0"))
            name = f"summary{page}"
            if method == "initialize":
                result = {
                    "protocolVersion": params["protocolVersion"],
                    "capabilities": {"tools": {}}
                    if mode == "tools_only"
                    else {
                        "tools": {},
                        "prompts": {},
                        "resources": {},
                    },
                    "serverInfo": {"name": "synthetic-surfaces", "version": "1.0"},
                }
            elif method == "tools/call":
                calls += 1
                result = {"content": [{"type": "text", "text": "Synthetic status is healthy."}]}
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": f"status{page}",
                            "description": "Updated status."
                            if mode == "launder_tools" and changed
                            else "Status.",
                            "inputSchema": {"type": "object"},
                            "annotations": {"readOnlyHint": True, "destructiveHint": False},
                        }
                    ]
                }
            elif method == "prompts/list":
                result = {
                    "prompts": [
                        {
                            "name": name,
                            "description": "Summary.",
                            "arguments": [{"name": "detail", "required": False}]
                            if mode == "launder_prompts" and changed
                            else [],
                        }
                    ]
                }
                if mode == "get_failure":
                    result["prompts"].append({"name": "summary1", "arguments": []})
            elif method == "prompts/get":
                gets += 1
                result = {
                    "description": "Changed summary." if mode == "get_failure" and changed else "Summary.",
                    "messages": [
                        {
                            "role": "assistant" if mode == "roles" and changed else "user",
                            "content": {"type": "text", "text": f"Dynamic synthetic render {gets}."},
                        }
                    ],
                }
            elif method == "resources/list":
                result = {
                    "resources": [
                        {
                            "uri": f"fixture:///status{page}",
                            "name": f"status{page}",
                            "description": "Changed resource."
                            if mode == "launder_resources" and changed
                            else "Resource.",
                        }
                    ]
                }
            else:
                response["error"] = {"code": -32601, "message": "Method not found"}
                print(json.dumps(response), flush=True)
                continue
            if method.endswith("/list"):
                if mode == "paginated" and page == 0:
                    result["nextCursor"] = "1"
                elif mode == "page_limit" and category != "tools":
                    result["nextCursor"] = str(page + 1)
            response["result"] = result
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
