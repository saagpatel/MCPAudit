# External Outreach Messages

Use these as starting points for direct field-report outreach. Lead with the
zero-install browser hook (5 seconds, no commitment), then ask for the redacted
CLI report as the actual contribution. Keep every ask small, safe, and explicit
about redaction.

## The hook: the hosted browser checker

The fastest way to get someone to engage is the hosted page, which needs no
install: [`mcp-audit.saagarpatel.dev`](https://mcp-audit.saagarpatel.dev). Paste
an MCP config, get a config-only trust report in the browser. It runs the exact
`mcp-audits` engine in config-only mode, never launches a server, never makes a
network request, and stores nothing. The redacted CLI report is the follow-up
ask, not the entry fee.

## Direct Ask For First Tester

```text
Built a thing you might find useful: paste your MCP config (Claude Desktop /
Cursor / Windsurf / Claude Code) at https://mcp-audit.saagarpatel.dev and it
shows what each server can actually touch (files, shell, network) plus what to
review before you connect. No install, nothing stored, runs in your browser.

If it surfaces anything interesting on your setup, the most helpful thing you
could do is drop a redacted report. One command, no server is launched and
nothing is contacted:

uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Then open a redacted field-report issue here:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

--skip-connect means MCPAudit does not spawn MCP servers or contact remote
endpoints. --redact scrubs hostname, home-path usernames, and server names.
Please still review the output and remove credentials, private paths, internal
hostnames, private URLs, customer/workspace names, and proprietary
prompt/resource/tool schema text before posting.
```

## Direct Ask For Second Tester

```text
If you run MCP servers, you can see their reach without installing anything:
https://mcp-audit.saagarpatel.dev to paste a config and get a config-only trust
report. A redacted report from a different MCP setup or consumer path would help
me a lot toward beta readiness.

uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Then open a redacted field-report issue here:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

The useful difference could be OS, MCP client mix, server shape, CI/dashboard
ingestion, or parser workflow. Please review the output before posting and
remove anything private, credential-bearing, internal, customer-specific, or
proprietary.
```

## Community Post (MCP / AI-tooling Discord, Slack, or forum)

```text
If you run MCP servers, you can now see their reach without installing anything:
https://mcp-audit.saagarpatel.dev to paste a config and get a config-only trust
report (file/shell/network/exfiltration surface + config-health flags). Runs
fully in-browser, never launches a server, never makes a network request,
stores nothing.

It is the hosted front door to mcp-audit (PyPI: mcp-audits), a local CLI that
adds the deeper connected checks: prompt-injection in tool descriptions, SSRF,
the lethal trifecta, schema drift, SARIF + a GitHub Action.

It is pre-beta and I want real scrutiny. If you can spare two minutes, a
redacted config-only report is the single most useful thing:

uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
then: https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

False positives, heuristics, anything that looks wrong: all fair game.
```

## Maintainer Follow-Up

```text
Thanks. The useful bits are version, OS, MCP clients, approximate server count,
status counts, config-health finding types, whether a consumer parsed the
output, and whether the redacted shape may become a public fixture.

Field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md
```

## Boundaries

Do not ask for:

- credential values;
- private paths or usernames;
- internal hostnames or private URLs;
- customer/workspace names;
- proprietary prompt, tool, resource, or schema text.

Route security-sensitive false negatives to `SECURITY.md`.
