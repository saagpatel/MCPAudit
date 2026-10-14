# mcp-audits-proof

Proof Before Action, packaged separately from MCPAudit. It reports what a
command did inside a disposable boundary and how that differed from its
declaration. It does not depend on `mcp-audits`, and it shares the
`mcp-audits` version.

## Install

Status: scaffolding. Until the Proof modules move into this distribution, this
package is empty and `proof-before-action` is still provided by `mcp-audits`.

Install it as its own tool so that `proof-before-action` is on your PATH:

```sh
uv tool install mcp-audits-proof
```

The `mcp-audits[proof]` extra installs this distribution too, but `uv tool`
exposes only the root package's console scripts, so the extra does not put
`proof-before-action` on your PATH.

## Use

```sh
proof-before-action --help
```

## Documentation

- [Proof Before Action](https://github.com/saagpatel/MCPAudit/blob/main/docs/labs/PROOF-BEFORE-ACTION.md)
- [Proof Before Action threat model](https://github.com/saagpatel/MCPAudit/blob/main/docs/labs/PROOF-BEFORE-ACTION-THREAT-MODEL.md)
- [MCPAudit](https://github.com/saagpatel/MCPAudit/blob/main/README.md)

## License

MIT. See [LICENSE](https://github.com/saagpatel/MCPAudit/blob/main/LICENSE).
