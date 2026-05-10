# Prompt And Resource Scoring Boundary

MCPAudit reports tool, prompt, and resource risk signals. The composite server
score remains tool-centered, and prompt/resource risk is exposed through the
additive `non_tool_risk` field.

## Current Behavior

- Tool permission findings contribute to `risk_score.composite`.
- Prompt and resource capability findings are visible in terminal, JSON, SARIF,
  and local policy gates.
- Prompt and resource injection findings are visible in terminal, JSON, SARIF,
  and local policy gates when `scan --inject-check` is used.
- Prompt and resource capability or injection findings contribute to
  `non_tool_risk` in JSON and terminal output.
- Prompt and resource findings do not currently change
  `risk_score.composite`.

## Rationale

Prompt and resource signals are meaningful, but merging them directly into the
existing tool score would change a published output contract without enough
calibration. A prompt with a risky argument and a tool that can execute shell
commands are related security signals, not necessarily equivalent scoring
inputs.

For `1.1.0`, MCPAudit keeps the stronger behavior contract: non-tool findings
are reportable, policy-gatable, and summarized in `non_tool_risk`, while
composite score semantics remain stable.

See `docs/SCORING-MIGRATION.md` for the migration path.
See `docs/COMPOSITE-SCORING-PROPOSAL.md` for a documented future combined-score
proposal that keeps current `risk_score.composite` semantics unchanged.

## Future Design Bar

Before prompt/resource findings affect the composite score, MCPAudit should add:

- documented weighting rules for tool, prompt, and resource targets;
- a migration note for CI users who gate on `risk_score.composite`.
- output-contract fixtures for any additive combined score field.

## Calibration Set

The calibration set should cover at least these cases before any composite score
migration:

| Target | Example signal | Expected behavior |
|--------|----------------|-------------------|
| Prompt argument | `command`, `script`, `endpoint`, `headers` | Emit capability findings and allow policy gates. |
| Prompt description | role-switch or instruction-override text | Emit injection findings when `--inject-check` is enabled. |
| File resource | `file:///...` | Emit `file_read` capability findings. |
| Remote resource | `https://`, `s3://`, `postgres://`, `github://` | Emit `network` capability findings. |
| Templated resource | URI variables such as `{tenant}` | Emit a review signal even when the scheme is custom. |
| Benign prompt/resource | local memo or summarization-only prompt | Emit no capability finding. |

Current tests cover these calibration rows and the additive `non_tool_risk`
field without changing `risk_score.composite`.
