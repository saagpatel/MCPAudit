# Composite Scoring Proposal

This proposal documents when prompt and resource findings could affect a future
server-level score. It does not change current `risk_score.composite` behavior.

## Current Decision

Keep `risk_score.composite` tool-centered for the compatible `1.x` line. Prompt
and resource findings remain visible through `capability_findings`,
`injection_findings`, `non_tool_risk`, SARIF, terminal output, and policy gates.

## Proposed Future Shape

If MCPAudit introduces a combined score later, make it additive instead of
changing `risk_score.composite` in place:

```json
{
  "risk_score": {
    "composite": 4.0
  },
  "non_tool_risk": {
    "composite": 5.95
  },
  "combined_risk": {
    "composite": 6.0,
    "tool_score": 4.0,
    "prompt_resource_score": 5.95
  }
}
```

This preserves existing CI consumers while giving users an opt-in migration path
for mixed tool, prompt, and resource triage.

## Candidate Weighting Rules

- Tool risk remains the primary signal because tools perform actions.
- High-severity prompt injection should contribute more than prompt argument
  keyword findings.
- Remote resources should raise review priority, but should not outweigh shell
  execution or destructive tool findings by themselves.
- Benign prompt/resource fixtures must remain quiet.
- Policy gates should continue to inspect findings directly instead of relying
  only on score thresholds.

## Fixture Evidence Available

The public non-tool calibration set now covers:

- documentation prompts and remote docs resources;
- local file resources;
- GitHub issue prompts and resources;
- PostgreSQL analytics resources;
- Slack thread export prompts and resources;
- calendar sharing prompts and resources;
- container registry publish prompts and resources;
- vault rotation prompt-injection and remote report resources;
- benign memory and glossary cases.

## Bar Before Implementation

Do not implement `combined_risk` until all of the following are true:

- at least two real-world redacted reports show that `non_tool_risk` alone is
  insufficient for triage;
- the proposed output shape is added to output-contract fixtures;
- policy examples document whether to gate on findings, `non_tool_risk`, or a
  new combined score;
- release notes clearly say that `risk_score.composite` remains unchanged.
