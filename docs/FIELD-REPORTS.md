# MCPAudit Field Reports

MCPAudit has a field-report lane for redacted setup evidence, consumer-contract
hardening, and external beta-readiness intake. This lane remains config-only by
default: collect shape and output evidence without spawning configured MCP
servers, contacting their remote endpoints, or storing credential values. Use
`--redact` for public reports so hostname, home-path usernames, and server names
are scrubbed from shared artifacts.

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
uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
uvx --from mcp-audits mcp-audit --version
```

The first line is the one-command report path and does not install MCPAudit into
a project or global environment.
uvx may contact the configured Python package index and may reuse uv's tool
cache. The MCPAudit scan itself avoids spawning stdio servers and avoids
contacting configured remote HTTP/SSE endpoints.
`--redact` scrubs hostname, home-path usernames, and server names from
JSON/SARIF/HTML artifacts; contributors still need to review for credential
values, internal hostnames, private URLs, and proprietary prompt/tool/schema
text before posting publicly. A useful report includes:

- MCPAudit version, operating system, client names, and approximate server
  count;
- status counts and config-health finding types;
- whether a JSON, SARIF, dashboard, or CI consumer parsed the report;
- the smallest redacted report or config snippet that shows the setup shape;
- discovery channel, first-run status, unassisted completion, elapsed-time
  band, and any onboarding or redaction friction;
- intent to repeat and, 7-14 days later, whether another config-only scan
  occurred;
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

## Activation And Repeat Evidence Contract

This contract keeps distribution, activation, repeat use, and product learning
separate:

- **Distributed** means a public package or delivery surface exists. Package
  downloads are a distribution proxy, not proof of a person completing a scan.
- **Completed** means an external operator generated a config-only report and
  reviewed it for safe redaction.
- **Unassisted** means that completion happened without synchronous maintainer
  help. Clarification or triage after the run does not change that status.
- **Valid external report** means the report meets the acceptance bar below and
  comes from outside the maintainer checkout. Self-tests and CI never count.
- **Repeat** means the same reporter confirms another config-only scan 7-14
  days later. A second public report is not required.
- **Product learning** means a valid report produces an accepted fixture,
  documented product change, or documented no-change decision.

For a separately authorized ten-participant validation cohort, the **pass** bar
is all of the following within 14 days:

- at least 6 of 10 participants complete safely and unassisted;
- at least 3 valid external reports cover at least 2 MCP client types;
- at least 2 participants repeat after 7 days; and
- at least 2 reports produce an accepted fixture or documented no-change
  decision.

The **kill or redesign** bar is any of the following:

- fewer than 3 participants complete;
- fewer than 2 valid external reports arrive;
- the evidence consists only of maintainer, self-test, or CI activity; or
- more than 2 participants cannot redact safely.

Recruitment, direct outreach, participant contact, and cohort execution require
separate authority. Until then, these are readiness and adjudication contracts,
not evidence that a cohort ran. Keep only aggregate funnel counts; do not add
visitor tracking or collect raw configs, identities, or private report content.

## Minimal Public Example

This is an example shape only, not an accepted external field report. It shows
the level of detail that is useful in a public issue after the report has been
generated with `--redact` and manually reviewed.

```text
MCPAudit version: mcp-audit, version X.Y.Z
Operating system: macOS / Darwin
MCP clients included: Claude Desktop and Cursor
Approximate server count: 3
Status counts: 3 skipped
Config-health finding types: remote_endpoint, package_runner_source_review
Consumer check: dashboard parser loaded the JSON report successfully
Discovery channel: PyPI
First run: yes
Unassisted completion: yes, under 5 minutes
Seven-day repeat: not due yet
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

Keep the current public release stable but pre-beta.

Reason: the scanner, field-report template, redaction path, compatibility
fixtures, and consumer examples are ready for external validation, but the beta
label remains blocked until at least two external redacted reports confirm the
current JSON/SARIF contract and downstream consumer path.

## Historical Field-Report Decisions

These decisions are kept as an evidence ledger for the `1.5.x` field-report
work. They do not change the current public-release pre-beta gate.

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
