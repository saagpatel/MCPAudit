# Prompt And Resource Scoring Migration

MCPAudit should not merge prompt/resource findings directly into
`risk_score.composite` until users have a migration window. The current path is
an additive non-tool score first.

## Recommended Path

1. Keep `risk_score.composite` tool-centered through `1.x`.
2. Expose prompt/resource capability and injection signals through additive
   `non_tool_risk`.
3. Calibrate `non_tool_risk` with validation fixtures before exposing it to
   policy defaults.
4. After at least one release window, decide whether to fold selected non-tool
   signals into a new composite score.

## Proposed Non-Tool Dimensions

| Dimension | Sources | Notes |
|-----------|---------|-------|
| prompt_arguments | risky prompt argument names such as `command`, `script`, `endpoint`, `headers` | Indicates a prompt can guide high-risk user input. |
| prompt_injection | prompt descriptions with role-switch or instruction-override text | Already policy-gatable through injection findings. |
| resource_local | `file://` and path-like resources | Should remain separate from tool file access. |
| resource_remote | `https://`, `s3://`, `postgres://`, `github://`, websocket, and cloud schemes | Indicates data can be fetched from or linked to external systems. |
| resource_template | URI variables such as `{tenant}` | Review signal for dynamic resource addressing. |

## Compatibility Rules

- Any new score field must be additive.
- Existing `risk_score.composite` semantics must not change in a compatible
  `1.x` release.
- Policy examples should not gate on a new score until fixtures and docs explain
  expected false-positive and false-negative behavior.
- SARIF rule IDs should stay tied to findings, not score dimensions.

## Current Decision

For `1.1.0`, prompt/resource findings remain reportable and policy-gatable, and
they also feed additive `non_tool_risk`. They remain out of
`risk_score.composite`. This preserves the current contract while giving users a
clearer triage signal for non-tool MCP capability risk.
