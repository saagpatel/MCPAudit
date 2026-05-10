# External Outreach Messages

Use these messages to collect the two external redacted field reports required
before MCPAudit uses a beta label. These asks intentionally use
`scan --skip-connect` so MCPAudit does not spawn MCP servers or contact remote
endpoints.

Primary request packet: `docs/EXTERNAL-FIELD-REPORT-REQUEST.md`.

Tracking:

- first external report: <https://github.com/saagpatel/MCPAudit/issues/83>
- second external report: <https://github.com/saagpatel/MCPAudit/issues/84>
- fixture conversion and beta decision:
  <https://github.com/saagpatel/MCPAudit/issues/85>

## Direct Ask For First Tester

```text
Could you help validate MCPAudit beta readiness by running one config-only field report from your MCP setup?

It should not spawn MCP servers or contact remote endpoints:

python3 -m pip install --upgrade mcp-permission-audit
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json

Then open a redacted field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

Please redact credentials, private paths, internal hostnames, private URLs, customer names, workspace names, and proprietary prompt/resource/tool/schema text.

Request packet:
https://github.com/saagpatel/MCPAudit/blob/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md
```

## Direct Ask For Second Tester

Use this for someone with a meaningfully different setup or consumer path than
the first tester, such as a different MCP client mix, operating system,
dashboard parser, CI parser, or server shape.

```text
Could you help validate MCPAudit beta readiness from a different MCP setup or report consumer path?

The request is config-only, so it should not spawn MCP servers or contact remote endpoints:

python3 -m pip install --upgrade mcp-permission-audit
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json

Then open a redacted field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

Please include the MCPAudit version, OS, client names, approximate server count, status counts, config-health finding types, whether any JSON/SARIF/dashboard/CI consumer parsed the report, and whether a redacted shape may become a public fixture.

Please redact credentials, private paths, internal hostnames, private URLs, customer names, workspace names, and proprietary prompt/resource/tool/schema text.

Request packet:
https://github.com/saagpatel/MCPAudit/blob/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md
```

## Public Post

```text
MCPAudit is looking for two redacted config-only field reports before moving toward beta.

If you use MCP servers with Claude Desktop, Claude Code, Cursor, VSCode, Windsurf, or another MCP client, this should take a few minutes:

python3 -m pip install --upgrade mcp-permission-audit
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json

Then open a redacted field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

The scan is config-only: it should not spawn MCP servers or contact remote endpoints.

Please redact credentials, private paths, internal hostnames, private URLs, customer names, workspace names, and proprietary prompt/resource/tool/schema text.

Details:
https://github.com/saagpatel/MCPAudit/blob/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md
```

## Follow-Up After A Report Lands

```text
Thank you. I will triage this against the MCPAudit external evidence checklist.

Before converting anything into a public fixture, I will confirm:

- the report used scan --skip-connect;
- no credential values, private paths, internal hostnames, private URLs, customer names, workspace names, or proprietary prompt/resource/tool/schema text are included;
- whether you gave permission to convert the redacted shape into a public fixture.

If anything looks sensitive, we will move it out of public issue triage and use the SECURITY.md disclosure path instead.
```

## Maintainer Handling

When a report arrives, use `docs/EXTERNAL-FIELD-REPORT-REQUEST.md#maintainer-triage`.
Keep #85 open until two accepted external reports have been handled. Solo
evidence in `docs/SOLO-EVIDENCE.md` can support confidence, but it does not
replace #83 or #84.
