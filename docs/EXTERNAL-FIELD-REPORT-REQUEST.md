# External Field-Report Request

Use this when asking a contributor for a safe, redacted MCPAudit report. The
goal is external output-contract evidence, not private workstation detail.

## Copy-Paste Request

```text
Could you help validate MCPAudit beta readiness by running one config-only field report?

Commands:

python3 -m pip install --upgrade mcp-audits
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

With --skip-connect, MCPAudit does not spawn MCP servers or contact remote
endpoints. With --redact, file artifacts alias server names and scrub hostname
and home-path usernames. Please still review the JSON before posting and remove
any credential values, private paths, internal hostnames, private URLs,
customer/workspace names, or proprietary prompt/tool/schema text.

Useful details:
- MCPAudit version
- operating system
- MCP clients included
- approximate server count
- status counts
- config-health finding types
- whether JSON/SARIF/dashboard/CI consumers parsed the report
- whether this redacted shape may become a public regression fixture

Field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md
```

## Maintainer Triage

When a report lands, triage it before treating it as beta evidence:

- Confirm it came from outside the maintainer checkout.
- Confirm it used `scan --skip-connect` and `--redact`.
- Confirm the public snippet avoids secrets, private paths, internal hostnames,
  private URLs, customer or workspace names, and proprietary prompt/tool/schema
  text.
- Capture MCPAudit version, operating system, MCP clients, approximate server
  count, status counts, config-health finding types, and any consumer parse
  result.
- Record whether the reporter granted fixture permission or needs private
  triage first.
- Classify the follow-up as field-report fixture, config-health fixture,
  consumer-example change, docs-only update, private security handling, bug fix,
  or no code change.

## Acceptance Bar

Accept a field report as beta evidence only when it:

- comes from outside the maintainer checkout;
- was produced from a config-only, redacted run;
- includes enough setup shape to exercise output consumers;
- avoids secrets, private paths, internal hostnames, private URLs, customer or
  workspace names, and proprietary prompt/tool/schema text;
- names whether fixture conversion is allowed.

Security-sensitive false negatives should go through `SECURITY.md`, not a
public issue.
