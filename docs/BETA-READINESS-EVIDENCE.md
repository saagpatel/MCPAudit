# MCPAudit Beta Readiness Evidence

MCPAudit `2.1.0` is a stable public package release, but it is still pre-beta
for external-evidence purposes. The current evidence shows that reports remain
compatible with older JSON shapes, records config-only findings from real local
MCP setup shapes, verifies checked-in JSON consumers against redacted
field-report fixtures, documents how to collect external redacted field reports
safely, tracks the remaining external evidence issues, and includes a copy-paste
request packet for contributors.

Solo multi-environment checks are tracked in `docs/SOLO-EVIDENCE.md`. They can
reduce install and documentation risk, but they do not replace the two external
redacted reports required before beta.

Tracked milestone: <https://github.com/saagpatel/MCPAudit/milestone/2>
Field-report milestone: <https://github.com/saagpatel/MCPAudit/milestone/3>
External field-evidence milestone:
<https://github.com/saagpatel/MCPAudit/milestone/4>

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
fixtures, so the evidence lane adds compatibility and documentation hardening
rather than new diagnostics.

The field-report pass keeps the same scanner boundary and adds redacted fixtures
for mixed, single-client, and quiet config-only setup shapes. Details live in
`docs/FIELD-REPORTS.md`.

## Output Contract Evidence

Upgrade compatibility now covers:

- older tool-only reports without prompt/resource additive fields;
- older failed-connection reports without top-level config-health fields;
- future additive fields at the report, audit, server, and finding levels.
- redacted field-report shapes parsed by the Python, Node, and dashboard
  consumer examples.

The compatibility decision remains:

- compatible releases may add optional fields;
- downstream consumers should ignore unknown fields;
- `risk_score.composite` remains tool-centered;
- prompt/resource risk remains additive through `non_tool_risk`.

## Current Decision

Keep `2.1.0` stable but pre-beta.

Reason: the current release strengthens downstream consumer confidence and
captures the field-report workflow, but it still does not include external
redacted reports. Keep the beta label blocked until at least two external
reports confirm the current JSON/SARIF contract and consumer examples.

The open external evidence issues are:

- <https://github.com/saagpatel/MCPAudit/issues/83>
- <https://github.com/saagpatel/MCPAudit/issues/84>
- <https://github.com/saagpatel/MCPAudit/issues/85>

The contributor request packet is `docs/EXTERNAL-FIELD-REPORT-REQUEST.md`.

## Historical Evidence Decisions

These decisions are kept as an evidence ledger for the `1.5.x` intake work.
They do not change the current `2.1.0` pre-beta gate.

Ship `1.5.1` as polish instead of `1.6.0`.

Reason: this pass strengthened compatibility evidence and docs, but it did not
add new user-facing scanner behavior. Reserve beta-prep feature work or
output-contract expansion for evidence backed by external redacted reports.

Ship `1.5.3` as polish instead of `1.6.0`.

Reason: this pass improved the external intake path for beta evidence, but it
still did not include external redacted reports. Keep the beta label blocked
until at least two external reports confirm the JSON/SARIF contract and consumer
examples.

Ship `1.5.4` as polish instead of `1.6.0`.

Reason: this pass made the external evidence blocker visible and trackable in
GitHub and public docs, but it still did not include the external reports needed
for beta.

Ship `1.5.5` as polish instead of `1.6.0`.

Reason: this pass made the external report ask easier to send and easier to
triage, but it still did not include the external reports needed for beta.
