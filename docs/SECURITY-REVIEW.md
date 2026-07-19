# Security Review Notes

This stable security review focuses on MCPAudit's own trust boundaries and the
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
- Proof Before Action observes a staged, commit-bound subject in a disposable
  Docker container and requires an exact image ID before image-provided observer
  tools run. Capsule verification recomputes the comparison, trust binding, and
  offline HTML projection against an explicit producer commit and an
  independently supplied root hash.
- Proof Before Action treats stale, masked, unmatched, unobservable, incomplete,
  dirty, or authority-unverified evidence as non-passing. A complete observation
  is not itself a claim that the tested action is generally safe.

## Remaining Risks

- MCP server metadata can contain adversarial text. Treat MCPAudit output as
  untrusted when feeding it into AI systems.
- Connected scans execute configured server commands. Use
  `scan --skip-connect` for first review or untrusted configs.
- Optional `--llm-analysis` sends selected metadata to a third-party API; do not
  use it for sensitive MCP configs.
- Proof Before Action is a bounded evidence collector, not a general sandbox.
  Its current Docker observer does not establish complete Unix-domain socket
  coverage, host-kernel isolation, or safety outside the declared and observed
  surfaces.
- Release-trust evidence remains only as authoritative as its independently
  supplied root and exact producer/subject bindings.
- Composite scoring is tool-centered in the stable line. Prompt/resource
  findings are reportable and policy-gatable, but score migration needs
  calibration first.

## Follow-Up Bar

Repeat this review before future releases that change config parsing,
connection lifecycle, redaction, scoring, SARIF generation, or LLM behavior.
Track the release gate in `docs/STABLE-READINESS.md`.
