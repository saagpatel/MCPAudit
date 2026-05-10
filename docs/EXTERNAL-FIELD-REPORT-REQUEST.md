# External Field Report Request

MCPAudit needs two external redacted field reports before any beta label is
used. This request is safe by default: it asks for config-only output, so
MCPAudit does not spawn MCP servers or contact remote endpoints.

Solo validation lives in `docs/SOLO-EVIDENCE.md`. It is useful for local
confidence, but it does not close the external evidence requirement.

Tracking:

- milestone: <https://github.com/saagpatel/MCPAudit/milestone/4>
- first report: <https://github.com/saagpatel/MCPAudit/issues/83>
- second report: <https://github.com/saagpatel/MCPAudit/issues/84>
- fixture conversion and beta decision:
  <https://github.com/saagpatel/MCPAudit/issues/85>

Maintainer outreach copy lives in `docs/EXTERNAL-OUTREACH-MESSAGES.md`.

## Copy-Paste Request

Please help MCPAudit validate its beta readiness by running one config-only
field report from your MCP setup.

```bash
python3 -m pip install --upgrade mcp-permission-audit
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json
```

Then open a redacted field-report issue:
<https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md>

Please include:

- MCPAudit version;
- operating system;
- MCP clients included, such as Claude Desktop, Claude Code, Cursor, VSCode, or
  Windsurf;
- approximate server count;
- whether a JSON, SARIF, dashboard, or CI consumer parsed the report;
- status counts and config-health finding types;
- the smallest redacted JSON or config snippet that shows the setup shape;
- whether the redacted shape may become a public fixture.

Do not include:

- API keys, tokens, passwords, cookies, or credential values;
- private file paths or usernames;
- internal hostnames, private URLs, customer names, or workspace names;
- proprietary prompt, resource, tool, or schema text that cannot be public.

If the report contains sensitive server metadata, proprietary prompt/resource
text, or a security-sensitive false negative, use private disclosure in
`SECURITY.md` instead of a public issue.

## Maintainer Triage

When a report arrives:

1. Confirm it was produced with `scan --skip-connect`.
2. Confirm it contains no credential values, private paths, internal hostnames,
   customer names, or proprietary prompt/resource/tool/schema text.
3. Confirm the reporter gave public fixture permission, or move the report into
   private triage.
4. Decide whether the report proves a new fixture, documentation clarification,
   consumer-example change, or no code change.
5. If it becomes a fixture, add the smallest redacted fixture and a regression
   assertion before closing the source issue.
6. After two accepted reports are handled, complete
   <https://github.com/saagpatel/MCPAudit/issues/85> with the release decision.

Do not change `risk_score.composite` from these reports alone. Keep behavior
changes tied to repeatable fixture evidence.
