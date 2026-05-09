# Security Review Notes

This beta security review focuses on MCPAudit's own trust boundaries and the
places where untrusted MCP metadata can affect reports.

## Reviewed Surfaces

- MCP client config discovery reads local files and does not write MCP client
  config during scans.
- Connected scans may spawn stdio servers or contact configured HTTP/SSE URLs;
  subprocess handling is guarded by timeouts and cleanup.
- Audited tool calls are never invoked. MCPAudit enumerates metadata only.
- Terminal, JSON, SARIF, and connection-error paths use the shared redaction
  layer for likely credential values.
- Prompt/resource injection findings are deterministic pattern matches unless
  optional LLM analysis is explicitly requested.
- JSON and SARIF now include target metadata for tool, prompt, and resource
  findings so downstream triage does not need to infer where a result came from.

## Remaining Risks

- MCP server metadata can contain adversarial text. Treat MCPAudit output as
  untrusted when feeding it into AI systems.
- Connected scans execute configured server commands. Use
  `scan --skip-connect` for first review or untrusted configs.
- Optional `--llm-analysis` sends selected metadata to a third-party API; do not
  use it for sensitive MCP configs.
- Composite scoring is tool-centered for the beta. Prompt/resource findings are
  reportable and policy-gatable, but score migration needs calibration first.

## Follow-Up Bar

Before stable `1.0.0`, repeat this review after any change to config parsing,
connection lifecycle, redaction, scoring, SARIF generation, or LLM behavior.
