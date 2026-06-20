# MCPAudit Launch Posts

## Hacker News

**Title:**

```text
Show HN: mcp-audit - see what your MCP servers can actually touch
```

**Body / first comment:**

```text
mcp-audit audits the MCP server configs already wired into your local tools and shows what each server can actually touch: file paths, shell/network access, risky tool schemas, and prompt/resource surfaces.

Repo: https://github.com/saagpatel/MCPAudit

The safest first pass is config-only and redacted:

mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Field reports are welcome here:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

Happy to answer anything about the heuristics, false positives, or how the scanner treats MCP servers without connecting to them.
```

## Notes

- Keep the launch copy pre-beta until at least two external redacted field reports land.
- Do not claim live user adoption from this copy alone.
