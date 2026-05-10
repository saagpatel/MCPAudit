# MCPAudit Field Reports

MCPAudit `1.5.3` has a field-report lane for redacted setup evidence,
consumer-contract hardening, and external beta-readiness intake. This lane
remains config-only by default: collect shape and output evidence without
spawning MCP servers, contacting remote endpoints, or storing credential values.

Tracked milestone: <https://github.com/saagpatel/MCPAudit/milestone/3>

Tracked issues:

- consumer contract coverage:
  <https://github.com/saagpatel/MCPAudit/issues/77>;
- redacted setup evidence:
  <https://github.com/saagpatel/MCPAudit/issues/78>;
- field-report docs:
  <https://github.com/saagpatel/MCPAudit/issues/79>;
- release decision:
  <https://github.com/saagpatel/MCPAudit/issues/80>.

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
mcp-audit scan --skip-connect --json mcp-audit-field-report.json
```

This mode avoids spawning stdio servers and avoids contacting remote HTTP/SSE
endpoints. A useful report includes:

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

## Release Decision

Ship `1.5.2` as polish instead of `1.6.0`.

Reason: this pass improves field-report readiness and downstream example
confidence, but it does not add scanner behavior or change the output schema.
Reserve `1.6.0` for a future beta-prep feature or output-contract expansion
backed by external redacted reports.

Ship `1.5.3` as polish instead of `1.6.0`.

Reason: this pass improves public field-report intake and beta-readiness
tracking, but it still does not include external redacted reports or change the
scanner/output contract.
