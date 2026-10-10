# Upstream issue draft: quadratic stdio line buffering

Status: prepared for dispatcher submission; no upstream issue has been filed.

The installed Python MCP SDK 2.3.0 `mcp/client/stdio.py` reader uses:

```python
lines = (buffer + chunk).split("\n")
buffer = lines.pop()
```

For a newline-delimited JSON-RPC response arriving in small pipe chunks,
every iteration copies and rescans the entire incomplete frame. Processing
a single line is quadratic in its byte length. The approved MCPAudit stress
finding H-06 reports a 256 MiB line reaching 9.2 GB RSS on the earlier SDK
reader. That is historical evidence, not a rerun against SDK 2.3.0.

Minimal reproduction of the reader algorithm (256 MiB, no server, config,
network or secrets):

```python
import time

frame_bytes = 256 * 1024 * 1024
chunk = "A" * 8192
buffer = ""
started = time.perf_counter()
for _ in range(frame_bytes // len(chunk)):
    lines = (buffer + chunk).split("\n")
    buffer = lines.pop()
lines = (buffer + "\n").split("\n")
assert len(lines[0]) == frame_bytes
print(time.perf_counter() - started)
```

This intentionally expensive reproduction should run only in an isolated
process with an external memory/deadline bound. It was not run here at
256 MiB. An end-to-end synthetic server reproduction is available using
`tests/fixtures/hostile_server.py oversized --frame-bytes 268435456` with
its required disposable `--work-dir`, cwd and HOME isolation, and the SDK
reader compatibility flag. Avoid that flag for ordinary hostile-server runs.

Suggested fix: retain incomplete frames in a bytearray, search only the new
chunk for newlines, and check a configurable frame cap before appending.
Decode only complete lines so split UTF-8 characters remain valid. Preserve
the existing session initialization, delivery backpressure and process
shutdown behavior. MCPAudit's replacement reader and fixture-backed tests
demonstrate this approach without changing the SDK handshake.
