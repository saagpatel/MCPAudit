# Beta Feedback To Fixtures

Beta feedback should become regression coverage whenever it describes a
repeatable false positive, false negative, output-shape problem, or policy gap.

## Intake Path

1. Ask for redacted MCP config, tool metadata, prompt/resource metadata, and the
   MCPAudit command that produced the result.
2. Classify the report as false positive, false negative, output contract,
   policy gate, pin lifecycle, or docs/adoption friction.
3. Add or update the smallest fixture that reproduces the case.
4. Add the expected finding, absence of finding, SARIF property, or policy
   violation assertion.
5. Keep credentials, internal hostnames, and private paths out of fixtures.

## Fixture Targets

- Permission false positives or negatives: `tests/validation/servers/*.json`.
- JSON/SARIF compatibility issues: `tests/fixtures/reports/` plus output
  contract snapshot tests.
- Policy gaps: `examples/policies/` and `tests/test_policy.py`.
- Pin lifecycle issues: `tests/test_pinning.py` or CLI pin tests.
- Documentation confusion: adoption, pin maintenance, security review, or
  output contract docs.

## Done Criteria

A beta feedback item is closed when the new fixture fails before the fix, passes
after the fix, and the changelog explains any user-visible behavior change.
