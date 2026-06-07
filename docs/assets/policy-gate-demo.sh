#!/usr/bin/env bash
set -uo pipefail

output=/tmp/mcp-audit-policy-gate.out

echo "$ mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --skip-connect --policy examples/policies/ci-strict.yaml"
mcp-audit scan \
  --config examples/configs/popular-public-servers.json \
  --config-only \
  --skip-connect \
  --policy examples/policies/ci-strict.yaml \
  >"${output}" 2>/dev/null
code=$?

awk 'seen || /Policy Gate Failed/ { seen=1; print }' "${output}" | head -n 42
echo
echo "exit code: ${code}"
