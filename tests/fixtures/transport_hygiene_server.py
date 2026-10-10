"""Local stdio peer for process and protocol hygiene acceptance tests."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import cast


def record(root: Path, pid: int, role: str) -> None:
    path = root / f"{role}-{pid}.json"
    path.write_text(json.dumps({"pid": pid, "pgid": os.getpgrp(), "role": role}))


def spawn_child(root: Path, ignore_sigterm: bool) -> None:
    child_code = (
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        if ignore_sigterm
        else "import time; time.sleep(60)"
    )
    child = subprocess.Popen([sys.executable, "-I", "-S", "-c", child_code])
    record(root, child.pid, "child")


def send(value: object) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main() -> None:
    mode = sys.argv[1]
    root = Path(sys.argv[2]).resolve()
    record(root, os.getpid(), "server")
    if mode in {"spawn-child-exit", "spawn-child-ignore"}:
        spawn_child(root, ignore_sigterm=mode == "spawn-child-ignore")
        return
    if mode == "stderr-malformed":
        for _ in range(100):
            sys.stderr.write("diagnostic marker token=synthetic-secret\n")
        sys.stderr.flush()
    for line in sys.stdin:
        request = cast(dict[str, object], json.loads(line))
        request_id = request.get("id")
        if request_id is None:
            continue
        if request.get("method") == "initialize":
            if mode in {"malformed", "malformed-flood", "stderr-malformed"}:
                for _ in range(50 if mode == "malformed-flood" else 1):
                    print(
                        f'{{"jsonrpc":"2.0","id":{json.dumps(request_id)},"result":'
                        "{bad json token=synthetic-secret",
                        flush=True,
                    )
                continue
            params = request.get("params")
            protocol = params.get("protocolVersion") if isinstance(params, dict) else "2025-06-18"
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": protocol,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fixture", "version": "1"},
                    },
                }
            )
            continue
        if request.get("method") == "tools/list":
            if mode == "hang":
                while True:
                    signal.pause()
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": [{"name": "status", "inputSchema": {"type": "object"}}]},
                }
            )
            continue
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )


if __name__ == "__main__":
    main()
