# Reading results

Read the coverage and connection status before treating an empty finding list
as reassuring. MCPAudit reports what it inspected and when a check was skipped
or incomplete.

## Risk score

The composite score is a 0–10 estimate of tool-centered capability exposure.
It is based on detected permission categories and their configured weights. A
higher score means a broader surface to review; it does not say that a server
is malicious. Prompt and resource signals are reported separately as
`non_tool_risk` and do not change `risk_score.composite`.

## Findings

Each finding includes a rule identifier, severity, evidence, and suggested
remediation where supported. Severity ranks the finding for review; it is not a
probability that an attack happened. Instruction-shaped text rules are
pattern-based heuristics and can have false positives or miss reworded text.
Annotation contradictions compare explicit server hints with observed keyword
evidence, not intent.

## Coverage and status

Check per-server connection state and warnings. Config-only checks do not
include tool metadata that requires a server connection. Failed connections,
unsupported inputs, limits, and skipped opt-in checks constrain what the report
can conclude. An empty `findings` list is not proof of complete coverage.

## Next steps

Review the named capability, compare the finding with the server's intended
role, and narrow permissions or configuration where useful. Repeat the check
after changes. For report fields and exit behavior, see the
[output contract](OUTPUT-CONTRACT.md); for automated triage, see the
[CI guide](guides/ci.md).
