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
Review config-health findings before turning on policy gates for remote
endpoints, shell-wrapper launches, deprecated transports, missing command paths,
project/global name conflicts, conflicting command or URL definitions,
package-runner launches, or duplicated server names.

## Team CI Policy Gate

Use a local policy file and keep reports even when the gate fails:

```bash
mcp-audit scan \
  --json mcp-audit.json \
  --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means the scan completed and report artifacts were written, but
the local policy failed.

Use `fail_on.config_health` when CI should fail on config setup findings:

```yaml
fail_on:
  config_health: medium
servers:
  github:
    fail_on:
      config_health: high
```

A complete JSON-plus-policy workflow example is available at
`examples/ci/generic-json-policy.yml`.

For a config-only gate focused on setup health, start from
`examples/ci/config-health-policy.yml`.

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

## GitHub Action (one-line)

For the turnkey path, use the composite action published from this repo
instead of hand-assembling install + scan + upload steps:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v6
  - uses: saagpatel/MCPAudit@v1.13.1
    with:
      args: --inject-check --ssrf-check --trifecta-check
      # sarif defaults to mcp-audit.sarif and uploads to code scanning
      # policy: examples/policies/balanced-team-ci.yaml  # gate the build (exit 2)
```

The action runs config-only by default (`skip-connect: "true"`), writes SARIF,
and uploads it to GitHub code scanning when `upload-sarif` is `true` (the
default). A failing `policy` makes the action exit `2` after the report is
written and uploaded, so the gate is enforced without losing the report.
Inputs are passed to the underlying command through environment variables, not
interpolated into the shell, so crafted input values cannot inject commands.

Available inputs: `version`, `args`, `skip-connect`, `clients`, `config`,
`policy`, `sarif`, `json`, `upload-sarif`, `working-directory`. Outputs:
`sarif-file`, `json-file`, `exit-code`.

## Pre-commit Hook

Audit repo-local MCP configs on every commit. The hook is config-only (it never
spawns or connects to servers) and triggers when a repo-root `.mcp.json` or a
`.vscode/mcp.json` changes:

```yaml
repos:
  - repo: https://github.com/saagpatel/MCPAudit
    rev: v2.0.0
    hooks:
      - id: mcp-audit
```

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
