# Build a trust packet

The trust-packet walkthrough pairs a local MCPAudit review with public,
reviewable information about a server. It is an evidence-organizing exercise,
not a certification or guarantee of runtime safety.

Start from a config-only review and keep the selected config explicit:

```sh
mcp-audit check --config ./mcp.json --output-json ./audit.json
```

Record the package or repository identity, version or pin, permissions granted,
findings, coverage warnings, and unresolved questions. Do not include secret
values or private prompt and tool text in a packet intended for sharing. Review
reports before distribution; redaction is best-effort.

The trust packet can help a reviewer decide whether a deeper connected check is
appropriate. A local report cannot establish publisher identity, external
review, production behavior, or downstream adoption. For the earlier detailed
ecosystem walkthrough, see the [trust packet background](../MCP-TRUST-PACKET.md).
