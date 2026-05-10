# MCPAudit Beta Readiness Evidence

MCPAudit `1.5.3` is a beta-readiness intake polish release. It does not change
scanner behavior or output schema. It adds evidence that current reports remain
compatible with older JSON shapes, records config-only findings from real local
MCP setup shapes, verifies checked-in JSON consumers against redacted
field-report fixtures, and documents how to collect external redacted field
reports safely.

Tracked milestone: <https://github.com/saagpatel/MCPAudit/milestone/2>
Field-report milestone: <https://github.com/saagpatel/MCPAudit/milestone/3>

## Local Evidence Pass

The evidence pass used config-only scans so no MCP servers were spawned and no
remote endpoints were contacted.

Observed setup shapes:

- a mixed local MCP setup with Claude Code and Claude Desktop configs;
- a Claude Code-only setup with global and project-scoped entries;
- a Claude Desktop-only setup with no config-health findings.

Observed config-health signals:

- duplicate server names;
- global/project server-name conflicts;
- package-runner launches;
- remote endpoint declaration;
- credential-heavy configs.

These signals are already covered by existing config-health behavior and
fixtures, so `1.5.1` adds compatibility and documentation hardening rather than
new diagnostics.

The `1.5.2` field-report pass keeps the same scanner boundary and adds redacted
fixtures for mixed, single-client, and quiet config-only setup shapes. Details
live in `docs/FIELD-REPORTS.md`.

## Output Contract Evidence

Upgrade compatibility now covers:

- older tool-only reports without prompt/resource additive fields;
- older failed-connection reports without top-level config-health fields;
- future additive fields at the report, audit, server, and finding levels.
- redacted field-report shapes parsed by the Python, Node, and dashboard
  consumer examples.

The compatibility decision remains:

- compatible `1.x` releases may add optional fields;
- downstream consumers should ignore unknown fields;
- `risk_score.composite` remains tool-centered;
- prompt/resource risk remains additive through `non_tool_risk`.

## Release Decision

Ship `1.5.1` as polish instead of `1.6.0`.

Reason: this pass strengthens compatibility evidence and docs, but it does not
add new user-facing scanner behavior. Reserve `1.6.0` for a future beta-prep
feature or output-contract expansion backed by external redacted reports.

Ship `1.5.2` as polish instead of `1.6.0`.

Reason: this pass strengthens downstream consumer confidence and captures the
current field-report workflow, but it still does not add scanner behavior or a
new output schema. Keep the beta label blocked on external redacted reports or a
reviewed output-contract expansion.

Ship `1.5.3` as polish instead of `1.6.0`.

Reason: this pass improves the external intake path for beta evidence, but it
still does not include external redacted reports. Keep the beta label blocked
until at least two external reports confirm the current JSON/SARIF contract and
consumer examples.
