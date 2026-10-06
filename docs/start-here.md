# Start here

MCPAudit reports what the MCP servers in a configuration declare they can
reach. Begin with an explicit config and a config-only scan; this avoids
discovering the current machine's client configs or starting their servers.

## First scan

From the repository root, use the synthetic example:

```sh
mcp-audit scan --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only --skip-connect --override-config /dev/null
```

For your own config, replace the example path with that file's path. Config
files can contain sensitive values; keep reports private and share only after
reviewing them.

## Choose a next step

- To understand the scan boundary, read [How it works](how-it-works.md).
- To interpret findings and warnings, read [Reading results](reading-results.md).
- To check a repository in CI, follow the [CI guide](guides/ci.md).
- To compare server schemas over time, follow the [pinning guide](guides/pinning.md).
- To learn through synthetic examples, open the [sandbox guide](guides/sandbox.md)
  or browse the [offline labs](labs/).

## Command map

| Need | Command or guide |
| --- | --- |
| See installed commands | `mcp-audit --help` |
| Scan a supplied file only | `mcp-audit scan --config FILE --config-only --skip-connect --override-config /dev/null` |
| List built-in session scenarios | `mcp-audit session-resume list` |
| Configure a CI policy | [CI guide](guides/ci.md) |
| Review baseline drift | [Pinning guide](guides/pinning.md) |
