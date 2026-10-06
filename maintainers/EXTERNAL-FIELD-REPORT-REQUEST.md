# External Field-Report Request

Use this when asking a contributor for a safe, redacted MCPAudit report. The
goal is external output-contract evidence, not private workstation detail or a
download-count proxy for adoption. Sending this request or recruiting a cohort
still requires the appropriate outreach and participant authority.

## Copy-Paste Request

```text
Could you help validate MCPAudit beta readiness by running one config-only field report?

One command generates the report without a project or global install:

uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Please also capture the resolved MCPAudit version:

uvx --from mcp-audits mcp-audit --version

uvx may contact the configured Python package index to resolve MCPAudit and may
reuse uv's tool cache. The MCPAudit scan itself does not spawn configured MCP
servers or contact their remote endpoints when --skip-connect is set. With
--redact, file artifacts alias server names and scrub hostname and home-path
usernames. Please still review the JSON before posting and remove any credential
values, private paths, internal hostnames, private URLs, customer/workspace
names, or proprietary prompt/tool/schema text.

Useful details:
- MCPAudit version
- operating system
- MCP clients included
- approximate server count
- status counts
- config-health finding types
- whether JSON/SARIF/dashboard/CI consumers parsed the report
- where you discovered MCPAudit
- whether this was your first run
- whether you completed it without synchronous maintainer help
- approximate minutes from discovery to a redacted report
- any onboarding or redaction friction
- whether you expect to repeat the scan in about seven days
- whether this redacted shape may become a public regression fixture

Field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

If you are willing, update the same issue 7-14 days later with whether you ran
another config-only scan. No new config or report content is required for that
repeat-use readback.
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
- Capture the discovery channel, first-run status, unassisted completion,
  elapsed-time band, friction category, repeat intent, and later repeat
  readback when the reporter volunteers them.
- Record whether the reporter granted fixture permission or needs private
  triage first.
- Classify the follow-up as field-report fixture, config-health fixture,
  consumer-example change, docs-only update, private security handling, bug fix,
  or no code change.
- Keep self-tests, CI, package downloads, and maintainer-authored reports out of
  the external activation numerator. Do not infer human completion or repeat
  use from package-download counts.

## Acceptance Bar

Accept a field report as beta evidence only when it:

- comes from outside the maintainer checkout;
- was produced from a config-only, redacted run;
- includes enough setup shape to exercise output consumers;
- avoids secrets, private paths, internal hostnames, private URLs, customer or
  workspace names, and proprietary prompt/tool/schema text;
- names whether fixture conversion is allowed.

Count an **unassisted completion** only when the reporter reaches a reviewed,
redacted report without synchronous maintainer help. Count a **repeat** only
when the same reporter confirms another config-only run 7-14 days after the
first. A repeat does not require another public report.

Security-sensitive false negatives should go through `SECURITY.md`, not a
public issue.
