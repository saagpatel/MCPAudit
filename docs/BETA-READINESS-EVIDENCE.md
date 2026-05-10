# MCPAudit Beta Readiness Evidence

MCPAudit `1.5.1` is a beta-readiness polish release. It does not change scanner
behavior or output schema. It adds evidence that current reports remain
compatible with older JSON shapes and records config-only findings from real
local MCP setup shapes.

Tracked milestone: <https://github.com/saagpatel/MCPAudit/milestone/2>

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

## Output Contract Evidence

Upgrade compatibility now covers:

- older tool-only reports without prompt/resource additive fields;
- older failed-connection reports without top-level config-health fields;
- future additive fields at the report, audit, server, and finding levels.

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
