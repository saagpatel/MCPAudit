# Synthetic sandbox

The repository sandbox teaches config-only analysis with synthetic config and
report fixtures. It does not require a live MCP server:

```sh
mcp-audit scan --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only --skip-connect --override-config /dev/null \
  --json /tmp/mcp-audit-sandbox.json
```

Review the [sandbox contents](../../examples/sandbox/README.md) for scenarios,
the checked-in static report, and the connected-tool manifest. The manifest is
an explanation of potential capabilities; it is not evidence that a live
server was started or tested.
