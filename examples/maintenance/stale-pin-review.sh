#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-mcp-audit-maintenance}"
mkdir -p "$out_dir"

mcp-audit discover > "$out_dir/discovered-servers.txt"
mcp-audit pin --status --json > "$out_dir/pin-status.json"
mcp-audit pin --stale --json > "$out_dir/stale-pins.json"

cat <<'MSG'
MCPAudit stale pin review written.

Review stale-pins.json first. If a listed server was intentionally removed,
clear only that server:

  mcp-audit pin --clear <server>

No pins were changed by this script.
MSG
