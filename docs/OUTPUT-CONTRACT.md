# Output Contract

MCPAudit reports are designed for local review and CI ingestion. Keep this
contract stable unless a release note calls out a breaking change.

For stable `2.x`, compatible minor and patch releases may add optional JSON
fields. Consumers should ignore unknown fields and should not fail when optional
fields are present. Existing stable fields should only be removed or renamed
with a release-note deprecation window and a breaking-version boundary.

## Exit Codes

- `0`: scan completed and no configured policy gate failed.
- `1`: command setup failed, such as invalid client or policy config.
- `2`: scan completed and report artifacts were written, but `--policy` failed.

## JSON Report

The JSON report is the serialized `AuditReport` model. Consumers should treat
unknown fields as additive. Important stable top-level fields:

- `scan_timestamp`
- `servers_discovered`
- `servers_connected`
- `servers_failed`
- `total_tools`
- `high_risk_servers`
- `audits`
- `config_health_findings`
- `policy_result`

Each audit may include:

- `tools`, `prompts`, and `resources`
- `permissions`
- `capability_findings`
- `injection_findings`
- `ssrf_findings`
- `trifecta_findings`
- `drift_findings`
- `risk_score`
- `non_tool_risk`

The report top level also includes:

- `fleet_trifecta_findings`
- `shadowing_findings`

`risk_score.composite` is tool-centered. `non_tool_risk` is an additive
prompt/resource triage signal and does not change `risk_score.composite`.
`non_tool_risk` may be `null` when a scan finds no prompt/resource capability or
injection findings.

`ssrf_findings` is an additive per-audit list populated only with `scan
--ssrf-check`. It flags tools and resources whose interface lets a caller steer a
server-side request target (URL/host parameters paired with fetch verbs, or
caller-templated remote resource hosts). It is static and schema-derived — no
request is issued and no credential value is read — and does not affect
`risk_score.composite`. Policies may opt in with `fail_on.ssrf`; the broad
`fail_on.severity` shortcut does not gate SSRF, so existing policy files keep
their previous behavior.

`config_health_findings` is an additive top-level list for pre-connection config
diagnostics. Findings include `finding_type`, `severity`, optional
`server_name`, `summary`, `details`, and `remediation`. Current finding types
include duplicate server names, missing stdio commands, deprecated SSE
transports, shell-wrapper launches, remote endpoints, remote URL arguments,
missing local command paths, project/global server-name conflicts, conflicting
server definitions, package-runner source review, and credential-heavy configs.
These findings do not affect `risk_score.composite`.
Policies may opt in to failing on this signal with `fail_on.config_health`; the
default broad `fail_on.severity` shortcut does not include config-health
findings, so existing policy files keep their previous behavior.

The generated JSON Schema for the current model is checked in at
`examples/schemas/audit-report.schema.json` and is tested against the live
Pydantic model.

Finding targets:

- tool permission and drift findings use `tool_name` and additive
  `target_type: "tool"` / `target_name` metadata
- prompt/resource capability findings use `target_type` and `target_name`
- injection findings include `tool_name` for compatibility and additive
  `target_type` / `target_name` fields for tool, prompt, and resource targets
- SSRF findings use `target_type` and `target_name` for tool and resource targets
- trifecta findings use `severity`, `is_fleet`, `leg1_contributors`,
  `leg2_contributors`, `leg3_contributors` (lists of `[server_name, tool_name]`
  pairs), `rule_id`, `title`, and `remediation`; per-server findings live on
  `ServerAudit.trifecta_findings`, fleet findings on
  `AuditReport.fleet_trifecta_findings`
- shadowing findings use `kind` (exact|normalized|homoglyph), `severity`, `name`
  (canonical/colliding tool name), `collisions` (list of `[server_name, tool_name]`
  pairs ordered with the first-configured/presumed-legitimate server first),
  `description`, `rule_id`, `title`, and `remediation`; all findings live on
  `AuditReport.shadowing_findings` (fleet-level only — collisions are inherently
  cross-server); populated only with `--shadow-check`; does not affect
  `risk_score.composite`; policies may opt in with `fail_on.shadowing`

Compatibility rules:

- additive optional fields are allowed in compatible stable releases;
- existing stable fields require a release-note deprecation window before
  removal or rename in a breaking release;
- SARIF rule IDs must remain stable unless a breaking release explicitly
  documents a migration.

## SARIF Report

SARIF output uses stable MCP rule IDs:

- `MCP001`-`MCP006`: permission categories
- `MCP007`-`MCP008`: prompt-injection findings
- `MCP009`: tool schema drift
- `MCP010`: policy gate violation
- `MCP011`-`MCP012`: SSRF findings
- `MCP013`: per-server lethal trifecta (HIGH)
- `MCP014`: fleet-level lethal trifecta advisory (MEDIUM)
- `MCP015`-`MCP017`: cross-server tool-name shadowing (exact / normalised / homoglyph)
- `MCP018`-`MCP019`: capability-escalation ("rug pull") vs pin baseline (capability gain / description-injection gain)
- `MCP020`-`MCP023`: launch-config / provenance drift vs pin baseline (command / args / url / credential key-names)
- `MCP024`: launch-artifact integrity drift vs pin baseline (on-disk binary/script hash change)
- `MCP025`: registry package-verification drift vs pin baseline (npm/PyPI published hash change; network, opt-in)
- `MCP026`: byte-level artifact verification vs pin baseline (downloaded bytes don't match the registry-published hash, or a pinned file changed/added since baseline; network, opt-in)

## Compatibility Fixture

The report fixtures in `tests/fixtures/reports/` cover representative connected,
failed, config-only, policy-failed, prompt/resource-heavy, SSRF, and trifecta reports. Tests
validate that fixtures still load through the current Pydantic models, generate
SARIF with the expected stable rules, and match the golden output-contract
snapshot in `tests/fixtures/reports/output_contract_snapshot.json`.

Upgrade compatibility fixtures in `tests/fixtures/reports/legacy/` cover older
report shapes that predate additive prompt/resource and config-health fields.
They also verify that future additive fields are ignored by the current model,
matching the stable compatibility rule for tolerant downstream consumers.

Redacted field-report fixtures in `tests/fixtures/reports/field/` cover mixed,
single-client, and quiet config-only setup shapes from real-world review paths.
The Python parser, Node parser, and dashboard summary examples are contract
tested against compatibility and field-report fixtures so output-consumer
friction can be turned into small regressions before the beta label.

## CI Examples

Write SARIF for GitHub code scanning:

```yaml
- name: Audit MCP servers
  run: mcp-audit scan --sarif mcp-audit.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-audit.sarif
    category: mcp-audit
```

Use JSON plus a local policy gate:

```bash
mcp-audit scan --json mcp-audit.json --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means reports were written but the policy gate failed.

Copy-paste workflow examples live in `examples/ci/`:

- `github-code-scanning.yml`
- `generic-json-policy.yml`
- `forge-then-audit.yml`
