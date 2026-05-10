# Solo Evidence

Solo evidence is useful for checking install paths, docs, output parsing, and
config-only safety before outside reports arrive. It is not external evidence
and does not close the external beta gate by itself.

Use this lane when MCPAudit needs momentum but no outside reporter is available
yet. Keep the public claim precise: solo evidence can reduce release risk, but
at least two external redacted reports are still required before using a beta
label.

## Scope

Solo evidence may cover:

- the published PyPI package path;
- a clean virtual environment install;
- a config-only scan of a real local setup;
- a hosted or CI smoke check when a safe sample config is available;
- downstream JSON, SARIF, dashboard, or CI consumer parsing.

Solo evidence must not:

- replace the external report issues;
- store raw workstation reports in the repository;
- include credential values, private paths, internal hostnames, private URLs,
  customer names, workspace names, or proprietary prompt/resource/tool/schema
  text;
- change `risk_score.composite` without repeatable fixture evidence.

## Recommended Solo Pass

Run the public package path:

```bash
uvx --from mcp-permission-audit mcp-audit --version
uvx --from mcp-permission-audit mcp-audit scan --skip-connect --json /tmp/mcp-audit-solo-local.json
```

Run a clean virtual environment path:

```bash
tmpdir=$(mktemp -d /tmp/mcp-audit-solo-clean.XXXXXX)
python3 -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install --upgrade pip
"$tmpdir/venv/bin/python" -m pip install mcp-permission-audit
"$tmpdir/venv/bin/mcp-audit" --version
"$tmpdir/venv/bin/mcp-audit" scan --skip-connect --json "$tmpdir/field-report.json"
rm -rf "$tmpdir"
```

If a hosted check is needed, use a redacted sample config or checked-in fixture.
Do not upload private local MCP configuration to CI.

## Recording Results

Record only the non-sensitive summary:

- MCPAudit version;
- install path used;
- operating system family;
- whether `scan --skip-connect` completed;
- server count, connection status counts, and high-risk server count;
- config-health finding types and counts;
- consumer parsing result, if tested;
- whether the evidence found a docs gap, fixture need, code issue, or no
  change.

Raw reports may be kept temporarily outside the repository for local triage,
then deleted. If a report contains sensitive security details, follow
`SECURITY.md` instead of public issue or docs intake.

## Evidence Log

### 2026-05-10 Solo Config-Only Pass

Status: completed.

Package paths checked:

- `uvx --from mcp-permission-audit==1.5.5 mcp-audit --version`;
- `uvx --from mcp-permission-audit==1.5.5 mcp-audit scan --skip-connect`;
- clean virtual environment install of `mcp-permission-audit==1.5.5`;
- clean virtual environment `mcp-audit scan --skip-connect`.
- checked-in fixture scan with
  `mcp-audit scan --config tests/fixtures/claude_desktop_config.json --config-only --skip-connect`.

Observed non-sensitive summary:

- version: `mcp-audit, version 1.5.5`;
- platform family: macOS/Darwin;
- discovered server entries: 19;
- connected servers: 0;
- failed connections: 0;
- connection statuses: 19 skipped;
- total tools: 0;
- high-risk servers: 0;
- config-health findings: 15;
- config-health finding types:
  - duplicate server name: 1;
  - conflicting global/project server name: 1;
  - package-runner source review: 10;
  - remote endpoint declaration: 1;
  - credential-heavy config: 2.

Decision: no code change required. The public package and clean virtual
environment install paths work for config-only scanning. This strengthens local
confidence but does not close issues #83, #84, or #85.

Fixture smoke summary:

- discovered server entries: 2;
- connected servers: 0;
- failed connections: 0;
- connection statuses: 2 skipped;
- total tools: 0;
- high-risk servers: 0;
- config-health findings: 2;
- config-health finding types:
  - package-runner source review: 2.

This fixture smoke is suitable for hosted or CI use because it does not depend
on private workstation MCP configuration.
