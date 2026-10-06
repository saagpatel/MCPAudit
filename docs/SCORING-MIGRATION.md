# Scoring Migration

## Annotation evidence in 2.9.0

Served `readOnlyHint=true`, `destructiveHint=false`, and `openWorldHint=false`
no longer suppress keyword capability evidence. Tools with contradicting
metadata can therefore score higher using the existing category weights and
confidence multipliers. Keyword matching and thresholds are unchanged.

Additive `audits[].annotation_findings` reports MCP043 contradictions at keyword
confidence MEDIUM or better. Destructive contradictions are HIGH (SARIF
`error`); other contradictions are MEDIUM (`warning`). Existing permission
severity policy gates also evaluate these findings. Contradictions carry no
extra numerical score. Honest annotations and null hints produce no
contradiction findings; absence of a keyword match is not evidence of a lie.

This item changes annotation suppression only. The linked change to honest
read-only declarations and missing-annotation default scoring is separate;
their current declared permission findings are retained here. Canary
eligibility continues to use served annotations as a veto.

## Prompt and resource scoring

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

`docs/COMPOSITE-SCORING-PROPOSAL.md` records the current proposal: add a future
`combined_risk` field if evidence justifies it, while preserving
`risk_score.composite` through the compatible `1.x` line.

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
