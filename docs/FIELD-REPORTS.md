# MCPAudit Field Reports

MCPAudit `1.5.2` adds a field-report lane for redacted setup evidence and
consumer-contract hardening. This lane remains config-only by default: collect
shape and output evidence without spawning MCP servers, contacting remote
endpoints, or storing credential values.

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
