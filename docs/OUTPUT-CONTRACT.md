# Output Contract

MCPAudit reports are designed for local review and CI ingestion. Keep this
contract stable unless a release note calls out a breaking change.

Before `1.0.0` stable, new fields may be added to JSON objects. Consumers
should ignore unknown fields and should not fail when optional fields are
present. Existing stable fields should only be removed or renamed with a
release-note deprecation window.

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
- `policy_result`

Each audit may include:

- `tools`, `prompts`, and `resources`
- `permissions`
- `capability_findings`
- `injection_findings`
- `drift_findings`
- `risk_score`

Finding targets:

- tool permission and drift findings use `tool_name` and additive
  `target_type: "tool"` / `target_name` metadata
- prompt/resource capability findings use `target_type` and `target_name`
- injection findings include `tool_name` for compatibility and additive
  `target_type` / `target_name` fields for tool, prompt, and resource targets

Compatibility rules:

- additive fields are allowed before `1.0.0` stable;
- existing stable fields require a release-note deprecation window before
  removal or rename;
- SARIF rule IDs must remain stable unless a breaking release explicitly
  documents a migration.

## SARIF Report

SARIF output uses stable MCP rule IDs:

- `MCP001`-`MCP006`: permission categories
- `MCP007`-`MCP008`: prompt-injection findings
- `MCP009`: tool schema drift
- `MCP010`: policy gate violation

## Compatibility Fixture

The report fixtures in `tests/fixtures/reports/` cover representative connected,
failed, config-only, policy-failed, and prompt/resource-heavy reports. Tests
validate that fixtures still load through the current Pydantic models and
generate SARIF with the expected stable rules.

## CI Examples

Write SARIF for GitHub code scanning:

```yaml
- name: Audit MCP servers
  run: mcp-audit scan --sarif mcp-audit.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

Use JSON plus a local policy gate:

```bash
mcp-audit scan --json mcp-audit.json --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means reports were written but the policy gate failed.
