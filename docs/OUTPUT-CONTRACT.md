# Output Contract

MCPAudit reports are designed for local review and CI ingestion. Keep this
contract stable unless a release note calls out a breaking change.

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

## SARIF Report

SARIF output uses stable MCP rule IDs:

- `MCP001`-`MCP006`: permission categories
- `MCP007`-`MCP008`: prompt-injection findings
- `MCP009`: tool schema drift
- `MCP010`: policy gate violation

## Compatibility Fixture

`tests/fixtures/reports/sample_audit_report.json` is a representative report
fixture. Tests validate that it still loads through the current Pydantic models.
