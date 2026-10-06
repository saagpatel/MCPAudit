# Start here

MCP servers are programs that an AI client can use to reach tools and data. Their
configured commands, arguments, and endpoints help show the possible access,
but do not tell the whole story. MCPAudit gives you a local inventory and
reviewable findings.

## 1. See a sample first

```sh
mcp-audit demo
```

The demo uses a bundled synthetic configuration. It does not discover your
client configs or connect to an MCP server.

## 2. Review your configuration

```sh
mcp-audit
```

Bare invocation runs the static `check` path. To select one file explicitly:

```sh
mcp-audit check --config ./mcp.json
```

An explicit config selects only that file unless `--include-discovered` is
given. Static checks do not start servers. See [How it works](how-it-works.md)
for discovery and connection boundaries.

## 3. Choose a next action

Read the suggested action and inspect the capability or text that triggered the
finding. Narrow a server's configured access when appropriate, then repeat the
review. A high score means broad capability exposure; it is not a malware
verdict. Pattern-based text checks are heuristics and can miss reworded or
obfuscated content.

See [Reading results](reading-results.md) for coverage and finding details.
For repeatable drift review, see [Pinning](guides/pinning.md). For automation,
see the [CI guide](guides/ci.md).

## Install for regular use

Install the `mcp-audits` package with [uv](https://docs.astral.sh/uv/); it
provides the `mcp-audit` command:

```sh
uv tool install mcp-audits
```

The package can also be run without a persistent installation:

```sh
uvx --from mcp-audits mcp-audit demo
```

See the [sandbox guide](guides/sandbox.md) to explore the synthetic example.
