# Adoption Guide

Use MCPAudit in the smallest mode that answers your current question. Start
with config-only review, then move to connected scans and policy gates after you
are comfortable with the configured MCP servers.

For a complete staged path from first inventory through CI gating, see
`docs/GOLDEN-ROLLOUT.md`.

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

To audit one explicit config file without also scanning workstation-discovered
configs, use `--config-only`:

```bash
mcp-audit scan --config ./mcp.json --config-only --inject-check
```

Review prompt/resource findings separately from the composite score. They are
visible in reports and policy gates. In `1.1`, they also feed the additive
`non_tool_risk` field, but they do not change `risk_score.composite`.

## Team CI Policy Gate

Use a local policy file and keep reports even when the gate fails:

```bash
mcp-audit scan \
  --json mcp-audit.json \
  --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means the scan completed and report artifacts were written, but
the local policy failed.

A complete JSON-plus-policy workflow example is available at
`examples/ci/generic-json-policy.yml`.

For stricter rollout, start from
`examples/policies/reviewed-local-workstation.yaml` or
`examples/policies/approved-servers-ci.yaml`. For browser-automation-heavy
MCP setups, start from `examples/policies/browser-automation-ci.yaml`.
The policy pack guide in `examples/policies/README.md` explains the intended
audience for each profile.

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

A complete GitHub code-scanning workflow example is available at
`examples/ci/github-code-scanning.yml`.

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

Run `mcp-audit pin --stale` during routine maintenance to find pin baselines for
servers that are no longer present in discovered MCP configs. See
`docs/PIN-MAINTENANCE.md` for the local helper script and scheduled CI example.

## Output Consumers

For JSON consumers, treat `risk_score.composite` as the stable tool-centered
score and `non_tool_risk` as optional prompt/resource triage metadata:

```bash
jq '.audits[] | {
  server: .server.name,
  tool_risk: .risk_score.composite,
  non_tool_risk: (.non_tool_risk.composite // 0)
}' mcp-audit.json
```

See `docs/1.1-ADOPTION.md` for more copy-paste parsing examples and
`examples/schemas/audit-report.schema.json` for the generated JSON Schema.
Runnable Python and Node consumer examples live in `examples/consumers/`.
