# External Outreach Messages

Use these as starting points for direct field-report outreach. Keep the ask
small, safe, and explicit about redaction.

## Direct Ask For First Tester

```text
Could you help validate MCPAudit beta readiness by running one config-only field report?

python3 -m pip install --upgrade mcp-audits
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Then open a redacted field-report issue here:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

With --skip-connect, MCPAudit does not spawn MCP servers or contact remote
endpoints. With --redact, it scrubs hostname, home-path usernames, and server
names. Please still remove credentials, private paths, internal hostnames,
private URLs, customer/workspace names, and proprietary prompt/resource/tool
schema text.
```

## Direct Ask For Second Tester

```text
Could you help validate MCPAudit beta readiness with a config-only field report
from a different MCP setup or consumer path?

python3 -m pip install --upgrade mcp-audits
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Then open a redacted field-report issue here:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

The useful difference could be OS, MCP client mix, server shape, CI/dashboard
ingestion, or parser workflow. Please review the output before posting and
remove anything private, credential-bearing, internal, customer-specific, or
proprietary.
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
