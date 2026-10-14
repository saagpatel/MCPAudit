# mcp-audits-labs

The MCPAudit offline labs and SafeForge, packaged separately from the core
`mcp-audits` review CLI. It shares the `mcp-audits` version and pins
`mcp-audits` to that exact version.

## Install

Install it through the core package's extra:

```sh
uv tool install 'mcp-audits[labs]'
```

## Use

The labs have no console scripts of their own. They run through the core CLI:

```sh
mcp-audit lab <topic> --help
mcp-audit safeforge preinstall|run
```

The labs explore bounded, synthetic, or experimental evidence contracts. Their
results do not establish production behavior or general ecosystem coverage.

## Documentation

- [Experimental labs](https://github.com/saagpatel/MCPAudit/blob/main/docs/labs/README.md)
- [SafeForge runtime threat model](https://github.com/saagpatel/MCPAudit/blob/main/docs/labs/SAFEFORGE-RUNTIME-THREAT-MODEL.md)
- [MCPAudit](https://github.com/saagpatel/MCPAudit/blob/main/README.md)

## License

MIT. See [LICENSE](https://github.com/saagpatel/MCPAudit/blob/main/LICENSE).
