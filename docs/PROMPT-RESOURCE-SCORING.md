# Prompt And Resource Scoring Boundary

MCPAudit reports tool, prompt, and resource risk signals, but the composite
server score is still tool-centered for the beta.

## Current Behavior

- Tool permission findings contribute to `risk_score.composite`.
- Prompt and resource capability findings are visible in terminal, JSON, SARIF,
  and local policy gates.
- Prompt and resource injection findings are visible in terminal, JSON, SARIF,
  and local policy gates when `scan --inject-check` is used.
- Prompt and resource findings do not currently change
  `risk_score.composite`.

## Rationale

Prompt and resource signals are meaningful, but merging them directly into the
existing tool score would change a published output contract without enough
calibration. A prompt with a risky argument and a tool that can execute shell
commands are related security signals, not necessarily equivalent scoring
inputs.

For the beta, MCPAudit keeps the stronger behavior contract: non-tool findings
are reportable and policy-gatable, while composite score semantics remain
stable.

## Future Design Bar

Before prompt/resource findings affect the composite score, MCPAudit should add:

- fixture-backed calibration across common MCP server types;
- documented weighting rules for tool, prompt, and resource targets;
- compatibility fixtures showing before/after report shapes;
- a migration note for CI users who gate on `risk_score.composite`.
