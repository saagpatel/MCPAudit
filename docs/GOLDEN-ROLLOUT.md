# Golden Rollout Path

Use this path when adopting MCPAudit on a workstation or in CI for the first
time. It starts with read-only config review, then adds live metadata, pins, and
policy gates only after the server set is understood.

## 1. Inventory Configured Servers

Start without spawning or contacting MCP servers:

```bash
mcp-audit discover
mcp-audit scan --skip-connect --json mcp-audit-config-review.json
```

Review discovered server names, commands, transports, package runners, remote
URLs, and credential key names. This pass is safe for exploratory review because
it does not connect to servers.

Resolve config-health warnings before creating pins. Duplicate names make a
reviewed pin baseline ambiguous because pins are keyed by server name. Missing
stdio commands, missing local command paths, project/global scope conflicts,
conflicting command or URL definitions, package-runner launches, deprecated SSE
transports, shell-wrapper launches, remote endpoints, and credential-heavy
configs deserve review before connected scans.
JSON reports include the same signal in `config_health_findings` for CI or
inventory consumers.

## 2. Run A Connected Review

After the configured servers look expected, inspect live MCP metadata:

```bash
mcp-audit scan --inject-check --json mcp-audit-connected.json
```

Connected scans may start stdio servers or contact HTTP/SSE servers. Review
tool findings, prompt/resource findings, and `non_tool_risk` separately from
`risk_score.composite`.

## 3. Create Reviewed Pins

Once a server set is reviewed, snapshot tool schemas:

```bash
mcp-audit pin
mcp-audit scan --pin-check --json mcp-audit-pinned.json
```

Use server-scoped maintenance commands for later changes:

```bash
mcp-audit pin --refresh github
mcp-audit pin --refresh github --apply
mcp-audit pin --stale
mcp-audit pin --clear github
```

`pin --refresh` is dry-run unless `--apply` is passed. `pin --stale` is
read-only and should be treated as a review prompt, not an automatic cleanup
step.

Pins are keyed by server name. If the same server name appears in more than one
discovered MCP config, rename the duplicate entries before pinning or refreshing
that baseline.

## 4. Add A Policy Gate

Start with the policy that matches the trust level of the environment:

```bash
mcp-audit scan \
  --inject-check \
  --pin-check \
  --json mcp-audit-policy.json \
  --policy examples/policies/balanced-team-ci.yaml
```

Use `examples/policies/local-review.yaml` for exploratory workstation review,
`examples/policies/reviewed-local-workstation.yaml` for reviewed local servers,
and `examples/policies/approved-servers-ci.yaml` when CI should only allow named
servers.
Use `examples/ci/config-health-policy.yml` when CI should fail on setup health
without connecting to MCP servers.

Exit code `2` means the scan completed and reports were written, but the local
policy failed.

## 5. Keep The Loop Calibrated

When MCPAudit misses something or reports too much, turn the smallest redacted
example into a fixture. Use `docs/FEEDBACK-TO-FIXTURES.md` for the intake path.

Do not change scoring defaults from one anecdote. Prefer several fixtures that
show the same false positive, false negative, output-shape issue, or policy gap.
