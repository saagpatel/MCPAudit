# Offline red-team foundation

This plain package is importable from a checkout and excluded from distributions.
It is a direct-detector harness, not an end-to-end CLI scan. It never connects to
a server or executes fixture code. Detector completion describes only the direct
call; it does not establish runtime safety.

`make base` scaffolds in a fresh directory under `build/redteam/` with mcpforge
from `MCPFORGE` or PATH, checks its version and allowlisted hashes, then removes
the temporary scaffold. It never installs dependencies or opens `.env.example`.
`make base REGEN=1` intentionally replaces the allowlisted baseline and extracted
surface. Review those diffs when changing mcpforge versions.

The AST extractor supports only literal FastMCP declarations and primitive tool
parameters. Unsupported module statements, decorators, metadata or types return
`UNKNOWN` with a reason. Function bodies are never evaluated. The extracted launch
config is synthetic `python server.py`, not a resolved executable or a connected
observation. Surface loaders reject environment value maps and retain key names.
Catalog fixtures are unversioned validation-corpus snapshots, not current verified
package metadata. Generated artifacts belong under ignored `build/redteam/`.

`redteam.range.harness.run_detectors` returns findings with their original check
IDs and a status for each detector: `completed`, `not_run` with a reason, or
`disabled`. Baseline checks need an explicit surface; fleet checks need companion
surfaces. `IntegrityInput` supplies expected relative-path hashes and current
bytes, which the adapter materializes in a disposable directory; it never opens
caller-supplied host artifact paths. Package verification requires an injected
fetch and carries `MOCKED` provenance. Missing inputs do not count as clean
checks. Unexpected detector errors propagate rather than becoming clean results.

Later range and chains packets share `surface.py` and `fixtures/servers/`; mutation
operators, chains logic and reports are outside this foundation.
