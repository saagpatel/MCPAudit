# MCPAudit Field Reports

MCPAudit `2.1.0` has a field-report lane for redacted setup evidence,
consumer-contract hardening, and external beta-readiness intake. This lane
remains config-only by default: collect shape and output evidence without
spawning MCP servers, contacting remote endpoints, or storing credential values.
Use `--redact` for public reports so hostname, home-path usernames, and server
names are scrubbed from shared artifacts.

Tracked milestone: <https://github.com/saagpatel/MCPAudit/milestone/3>
External evidence milestone:
<https://github.com/saagpatel/MCPAudit/milestone/4>

Tracked issues:

- consumer contract coverage:
  <https://github.com/saagpatel/MCPAudit/issues/77>;
- redacted setup evidence:
  <https://github.com/saagpatel/MCPAudit/issues/78>;
- field-report docs:
  <https://github.com/saagpatel/MCPAudit/issues/79>;
- release decision:
  <https://github.com/saagpatel/MCPAudit/issues/80>.

External evidence issues:

- first external redacted field report:
  <https://github.com/saagpatel/MCPAudit/issues/83>;
- second external redacted field report:
  <https://github.com/saagpatel/MCPAudit/issues/84>;
- fixture conversion and beta decision:
  <https://github.com/saagpatel/MCPAudit/issues/85>.

Contributor request packet:
`docs/EXTERNAL-FIELD-REPORT-REQUEST.md`.
Maintainer outreach copy:
`docs/EXTERNAL-OUTREACH-MESSAGES.md`.

Solo validation is tracked separately in `docs/SOLO-EVIDENCE.md`. It can
exercise published-package installs, clean virtual environments, and config-only
report parsing, but it does not replace the two external redacted reports
required for beta.

## Evidence Captured

The current field-report fixtures cover:

- a mixed setup with duplicate names, package-runner launches, a remote
  endpoint, and credential-heavy configuration;
- a single-client setup that only needs package-runner source review;
- a quiet setup with no config-health findings.

These are redacted report shapes, not raw workstation configs. They are stored
under `tests/fixtures/reports/field/` and load through the current output model.

## External Intake Path

External field reports should start with config-only output:

```bash
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
```

This mode avoids spawning stdio servers and avoids contacting remote HTTP/SSE
endpoints. `--redact` scrubs hostname, home-path usernames, and server names
from JSON/SARIF/HTML artifacts; contributors still need to review for credential
values, internal hostnames, private URLs, and proprietary prompt/tool/schema
text before posting publicly. A useful report includes:

- MCPAudit version, operating system, client names, and approximate server
  count;
- status counts and config-health finding types;
- whether a JSON, SARIF, dashboard, or CI consumer parsed the report;
- the smallest redacted report or config snippet that shows the setup shape;
- permission to convert the redacted example into a public fixture, or a note
  that private triage is needed first.

Do not collect credential values, private usernames, private paths, internal
hostnames, private URLs, customer names, workspace names, or proprietary
prompt/resource/tool/schema text. Security-sensitive false negatives should use
private disclosure in `SECURITY.md` instead of a public issue.

The dedicated GitHub template for this path is
`.github/ISSUE_TEMPLATE/field_report.md`.
The copy-paste request for contributors lives in
`docs/EXTERNAL-FIELD-REPORT-REQUEST.md`.

## Minimal Public Example

This is an example shape only, not an accepted external field report. It shows
the level of detail that is useful in a public issue after the report has been
generated with `--redact` and manually reviewed.

```text
MCPAudit version: mcp-audit, version 2.1.0
Operating system: macOS / Darwin
MCP clients included: Claude Desktop and Cursor
Approximate server count: 3
Status counts: 3 skipped
Config-health finding types: remote_endpoint, package_runner_source_review
Consumer check: dashboard parser loaded the JSON report successfully
Fixture permission: yes, a redacted shape may become a public fixture
```

Small redacted JSON snippets should preserve structure without exposing local
names, paths, hosts, URLs, credentials, or proprietary prompt/schema text:

```json
{
  "servers_discovered": 3,
  "servers_connected": 0,
  "servers_failed": 0,
  "audits": [
    {
      "server": {"name": "server-01", "client": "claude_desktop"},
      "connection_status": "skipped"
    }
  ],
  "config_health_findings": [
    {
      "server_name": "server-01",
      "finding_type": "package_runner_source_review",
      "severity": "medium"
    }
  ]
}
```

If the smallest useful snippet still needs private paths, internal hostnames,
private URLs, customer/workspace names, or proprietary tool/prompt/schema text,
do not post it publicly. Use private triage first.

## Fixture Acceptance Bar

A field report is ready to become a fixture when it answers:

- which setup or consumer shape it represents;
- which behavior should remain stable;
- which sensitive values were removed;
- whether the fixture belongs under `tests/fixtures/reports/field/`,
  `tests/fixtures/reports/legacy/`, `tests/fixtures/config_health/`, or another
  narrower test target.

Do not use a beta label until at least two external redacted reports confirm the
current output contract is stable for downstream consumers.

Use the external evidence milestone to keep this visible:
<https://github.com/saagpatel/MCPAudit/milestone/4>.

## Consumer Contract

The example consumers are now tested against the same compatibility set:

- `examples/consumers/parse_report.py`;
- `examples/consumers/parse-report.mjs`;
- `examples/consumers/dashboard_summary.py`.

The contract is intentionally simple:

- consumers should tolerate older reports missing additive fields;
- consumers should ignore future additive fields;
- consumers should preserve server counts and status counts;
- Python and Node compact summaries should agree for the same report.

## Current Decision

Keep `2.1.0` stable but pre-beta.

Reason: the scanner, field-report template, redaction path, compatibility
fixtures, and consumer examples are ready for external validation, but the beta
label remains blocked until at least two external redacted reports confirm the
current JSON/SARIF contract and downstream consumer path.

## Historical Field-Report Decisions

These decisions are kept as an evidence ledger for the `1.5.x` field-report
work. They do not change the current `2.1.0` pre-beta gate.

Ship `1.5.2` as polish instead of `1.6.0`.

Reason: this pass improved field-report readiness and downstream example
confidence, but it did not add scanner behavior or change the output schema.

Ship `1.5.3` as polish instead of `1.6.0`.

Reason: this pass improved public field-report intake and beta-readiness
tracking, but it still did not include external redacted reports or change the
scanner/output contract.

Ship `1.5.4` as polish instead of `1.6.0`.

Reason: this pass created the external evidence milestone and kept its three
tracking issues visible from the public docs, but it still did not include the
external redacted reports needed for beta.

Ship `1.5.5` as polish instead of `1.6.0`.

Reason: this pass added the contributor request packet and maintainer triage
checklist, but it still did not include the external redacted reports needed for
beta.
