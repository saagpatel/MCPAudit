---
name: Bug report
about: Report incorrect audit results, crashes, or unexpected behavior
title: "[bug] "
labels: bug
assignees: ''
---

## Description

A clear description of what went wrong.

## MCPAudit version

```
mcp-audit --version
```

## Python version

```
python --version
```

## MCP server type / config that triggered the issue

What type of MCP server were you auditing? (e.g., filesystem, fetch, custom, etc.)

Paste a **redacted** snippet of the relevant config block — remove any API keys, tokens, or sensitive paths:

```json
{
  "mcpServers": {
    "example-server": {
      "command": "...",
      "args": []
    }
  }
}
```

> **Note:** If this issue involves a security-relevant false negative (a threat that MCPAudit missed), consider using [private disclosure](../SECURITY.md) instead of a public issue.

## Command run

```bash
mcp-audit ...
```

## Expected behavior

What did you expect MCPAudit to report?

## Actual behavior

What did MCPAudit actually report? Paste the output (redacted if needed):

```
<paste output here>
```

## Additional context

Any other relevant details — OS, config file location, MCP client (Claude Desktop, Cursor, VS Code), etc.
