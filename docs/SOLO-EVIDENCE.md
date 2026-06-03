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

### 2026-06-02 Solo Pass — 1.12.0 Popular Public Server Field Scan

Status: completed.

Package path checked:

- `uvx --from mcp-permission-audit==1.12.0 mcp-audit --version`;
- config-only scan of a publishable sample config of popular **public** servers,
  `mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --skip-connect`.

The sample config (`examples/configs/popular-public-servers.json`) lists only
public open-source servers (the official `@modelcontextprotocol/*` npm servers,
the official `mcp-server-{git,fetch,time}` PyPI servers, plus a placeholder
`example.com` remote and a credential **key name** only). It contains no
credential values, private paths, internal hostnames, or proprietary text, so
it is safe to check in and run in CI.

Observed non-sensitive summary (config-only, no servers spawned):

- version: `mcp-audit, version 1.12.0`;
- platform family: macOS/Darwin;
- discovered server entries: 9;
- connected servers: 0; failed: 0; statuses: 9 skipped;
- total tools: 0; high-risk servers: 0;
- config-health findings: 9, all `medium`:
  - package-runner source review: 8;
  - remote endpoint declaration: 1.

Artifact-verification evidence (1.12.0, `MCP025` + `MCP026`, network, read-only —
no servers spawned, package bytes downloaded and hashed in memory):

- exercised the registry-metadata check (`MCP025`) and the byte-level download +
  hash check (`MCP026`) against the **real published packages** named in the
  sample config (7 exact-version refs; the one floating-version ref was correctly
  skipped because both checks key by exact `package@version`);
- registry-published hash retrievable: 7/7;
- bytes downloaded and hashed: 7/7;
- downloaded bytes matched the registry-published hash
  (`published_consistent`): **7/7**;
- per-file handling confirmed on real releases: npm refs resolved to a single
  tarball; PyPI refs resolved to two files each (sdist + wheel), and every file
  matched its published sha256.

Connected reference scan (separate, public OSS only): a connected scan of the
same public servers (which spawns the official reference implementations and
enumerates their real tool schemas — public, non-sensitive metadata) connected
to 7/9 servers, enumerated 64 tools, produced calibrated risk scores (the
GitHub server scored highest as the most capable surface; `fetch` and
`everything` each raised one SSRF finding consistent with their documented
behavior), and produced **no** prompt-injection findings on these clean servers.
The two non-connecting entries failed for benign config reasons (a non-existent
filesystem path and the `example.com` placeholder remote). Connected output is
not stored in the repo; only this non-sensitive summary is recorded.

Decision: no code change required. 1.12.0's public-package and config-only paths
work against real popular servers; `MCP025`/`MCP026` verify real npm + PyPI
artifacts end-to-end with zero false positives on untampered official packages.
This strengthens local confidence and gives a concrete, publishable artifact to
recruit external reporters, but it does **not** close issues #83, #84, or #85 —
two external redacted reports are still required before any beta label.
