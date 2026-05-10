---
name: Redacted field report
about: Share a config-only MCPAudit report that can inform beta readiness
title: "[field-report] "
labels: field-report, feedback
assignees: ''
---

## Field report type

- [ ] Config-only report from one MCP client
- [ ] Config-only report from multiple MCP clients
- [ ] JSON/SARIF consumer compatibility check
- [ ] Dashboard or CI ingestion check
- [ ] Documentation or adoption friction found while reporting
- [ ] Other

## Safety boundary

Please use config-only mode for public field reports.
This avoids spawning MCP servers and avoids contacting remote endpoints.

```bash
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json
```

If you need to share connected scan output, use private disclosure in
`SECURITY.md` first when the report includes sensitive server metadata,
proprietary prompt/resource text, or security-sensitive false negatives.

## Setup shape

- MCPAudit version:
- Operating system:
- MCP clients included, for example Claude Desktop, Claude Code, Cursor,
  VSCode, or Windsurf:
- Approximate server count:
- Was this report consumed by a dashboard, CI job, or script?

## What MCPAudit reported

Paste a small redacted summary of the result. Useful signals include status
counts, config-health finding types, policy failures, and JSON/SARIF consumer
friction.

## Minimal redacted report snippet

Paste the smallest redacted JSON, SARIF, or config snippet that shows the setup
shape or consumer issue.

Do not include:

- API keys, tokens, passwords, cookies, or credential values
- private file paths or usernames
- internal hostnames, private URLs, customer names, or workspace names
- proprietary prompt, resource, tool, or schema text that cannot be public

## Expected fixture value

If this became a public fixture, what should it help MCPAudit keep stable?

- [ ] Config-health finding behavior
- [ ] JSON/SARIF output compatibility
- [ ] Dashboard summary behavior
- [ ] Consumer parsing behavior
- [ ] Documentation or command guidance
- [ ] Beta-readiness evidence only

## Fixture permission

- [ ] I am comfortable with a redacted version of this example becoming a public
      fixture.
- [ ] This report may need private triage first.
