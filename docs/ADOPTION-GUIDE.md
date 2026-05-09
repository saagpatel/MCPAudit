# Adoption Guide

Use MCPAudit in the smallest mode that answers your current question. Start
with config-only review, then move to connected scans and policy gates after you
are comfortable with the configured MCP servers.

## Local Personal Audit

Start without spawning or contacting servers:

```bash
uvx --from mcp-permission-audit mcp-audit discover
uvx --from mcp-permission-audit mcp-audit scan --skip-connect
```

When you are ready to inspect live MCP metadata, run a connected scan:

```bash
mcp-audit scan --inject-check
```

Review prompt/resource findings separately from the composite score. They are
visible in reports and policy gates, but they do not yet change
`risk_score.composite`.

## Team CI Policy Gate

Use a local policy file and keep reports even when the gate fails:

```bash
mcp-audit scan \
  --json mcp-audit.json \
  --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means the scan completed and report artifacts were written, but
the local policy failed.

## GitHub Code Scanning

Export SARIF and upload it with GitHub's SARIF action:

```yaml
- name: Audit MCP servers
  run: mcp-audit scan --inject-check --sarif mcp-audit.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

Use `scan --skip-connect --sarif mcp-audit.sarif` for config-only CI where
starting local MCP servers is not appropriate.

## Pin Baselines

Use pins after a server set is reviewed:

```bash
mcp-audit pin
mcp-audit scan --pin-check
mcp-audit pin --refresh github
mcp-audit pin --refresh github --apply
```

Use `mcp-audit pin --clear <server>` only when the server was intentionally
removed from MCP client configuration.
