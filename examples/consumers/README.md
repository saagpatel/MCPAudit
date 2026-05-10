# Output Consumer Examples

These examples show how downstream tools can parse MCPAudit JSON reports without
depending on every field staying fixed forever.

The examples:

- tolerate unknown fields;
- treat `risk_score.composite` as the stable tool-centered score;
- treat `non_tool_risk` as optional additive prompt/resource metadata;
- treat `config_health_findings` as optional additive config metadata;
- summarize config-health findings by severity for each server;
- route findings by `target_type` and `target_name`.

Run them against any JSON report:

```bash
mcp-audit scan --inject-check --json mcp-audit.json
python examples/consumers/parse_report.py mcp-audit.json
python examples/consumers/dashboard_summary.py mcp-audit.json
node examples/consumers/parse-report.mjs mcp-audit.json
```

The parsing scripts print compact JSON summaries that are safe to feed into a CI
step or dashboard.
