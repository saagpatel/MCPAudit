# Use MCPAudit in CI

Start with a config-only workflow. It avoids starting MCP servers while still
letting a local policy evaluate available configuration evidence.

```yaml
- uses: actions/checkout@v6
- uses: saagpatel/MCPAudit@v2.8.1
  with:
    skip-connect: "true"
    sarif: mcp-audit.sarif
```

The Action defaults to config-only operation and uploads SARIF when enabled.
This example names the current repository release; check the release checklist
when updating it. Use a reviewed immutable revision where your workflow
requires a fixed source. Check the Action's current inputs in
[`action.yml`](../../action.yml).

## Local policy gate

Pass a repository-owned policy file through the Action's `policy` input, or run
the CLI with an explicit configuration:

```sh
mcp-audit check --config ./mcp.json --policy ./policy.yaml --sarif mcp-audit.sarif
```

Use policy thresholds that match the evidence available in CI. A failed policy
returns a nonzero status after requested artifacts are written. See the
[policy examples](../../examples/policies/README.md) and the
[output contract](../OUTPUT-CONTRACT.md).

Connected checks can execute configured local programs or contact endpoints.
Enable them only in a workflow where that reach is intended and reviewed.
