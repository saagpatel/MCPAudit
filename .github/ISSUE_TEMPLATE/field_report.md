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

Please use config-only mode for public field reports. The first command below
generates the report without a project or global install.

```bash
uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
uvx --from mcp-audits mcp-audit --version
```

uvx may contact the configured Python package index and may reuse uv's tool
cache. The MCPAudit scan itself avoids spawning MCP servers from configured
clients and avoids contacting remote endpoints configured by those clients.
`--redact` scrubs hostname, home-path usernames, and server names from the
shared report. Still review the output before posting: credential values,
internal hostnames, private URLs, and proprietary prompt/tool/schema text do
not belong in public issues.

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

## Activation path

These aggregate fields help distinguish distribution from successful use. Skip
anything you do not want to answer.

- Where did you discover MCPAudit? PyPI / MCP Registry / browser / GitHub / other:
- Was this your first MCPAudit run? yes / no:
- Did you complete the report without synchronous maintainer help? yes / no:
- Approximate minutes from discovery to a reviewed, redacted report:
- What onboarding or redaction friction, if any, did you hit?
- Do you expect to run another config-only scan in about seven days? yes / no / unsure:

## What MCPAudit reported

Paste a small redacted summary of the result. Useful signals include status
counts, config-health finding types, policy failures, and JSON/SARIF consumer
friction. See `docs/FIELD-REPORTS.md#minimal-public-example` for a safe example
shape.

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

## Seven-day repeat readback

If you return 7-14 days later, no new config or report content is required.

- Did you run another config-only scan? yes / no:
- Repeat date:
- Same setup or a different setup?
- Did the result change a review, configuration, or trust decision? Optional
  aggregate summary only:
