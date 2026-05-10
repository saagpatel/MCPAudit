# Feedback To Fixtures

User feedback should become regression coverage whenever it describes a
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

The public feedback issue template mirrors this intake path. A fixture-ready
report should include:

- the MCPAudit version and exact command mode;
- the smallest redacted config, tool, prompt, resource, policy, pin, JSON, or
  SARIF snippet that reproduces the issue;
- the expected regression assertion, such as a missing finding, unwanted
  finding, target metadata mismatch, policy result, or pin lifecycle behavior;
- confirmation that the redacted example can become a public fixture, or a note
  that private triage is needed first.

## Fixture Targets

- Permission false positives or negatives: `tests/validation/servers/*.json`.
- JSON/SARIF compatibility issues: `tests/fixtures/reports/` plus output
  contract snapshot tests.
- Policy gaps: `examples/policies/` and `tests/test_policy.py`.
- Pin lifecycle issues: `tests/test_pinning.py` or CLI pin tests.
- Documentation confusion: adoption, pin maintenance, security review, or
  output contract docs.

## Active Follow-Up Lanes

Use these lanes to decide whether feedback is ready for implementation or
should remain in observation.

### Prompt And Resource Scoring

Completed issue: <https://github.com/saagpatel/MCPAudit/issues/61>

Before changing `risk_score.composite`, collect prompt/resource fixtures from
multiple server families. A useful fixture includes:

- prompt and resource names, descriptions, argument names, and URI templates;
- expected `non_tool_risk` categories and severities;
- at least one benign prompt/resource example that should not add risk;
- a short rationale for why composite scoring would help users triage the case.

Current public calibration coverage includes documentation, filesystem, GitHub,
PostgreSQL, Slack, calendar, container registry, and vault-style examples, plus
benign memory and glossary cases. Keep adding fixtures here before changing
composite scoring.
`docs/COMPOSITE-SCORING-PROPOSAL.md` documents the future combined-score
proposal without changing current `risk_score.composite` behavior.

### Dashboard JSON Consumers

Completed issue: <https://github.com/saagpatel/MCPAudit/issues/59>

Before adding new JSON fields or CLI flags for dashboards, collect examples from
real consumers. A useful report includes:

- the dashboard or CI system consuming the JSON;
- the fields that were hard to use, missing, or too unstable;
- a redacted input report and the desired dashboard summary;
- whether the current `examples/consumers/dashboard_summary.py` output was
  sufficient.

The checked-in `tests/fixtures/reports/dashboard_status_report.json` fixture
models a mixed status page input with config-health, non-tool risk, policy, and
failed-connection signals.
`examples/consumers/dashboard_summary.py` now emits status counts, max risk
scores, policy failure count, and attention rows for status pages.

### Stale Pin Cleanup

Completed issue: <https://github.com/saagpatel/MCPAudit/issues/60>

Bulk stale-pin cleanup is available through `pin --clear-stale`. It is dry-run
by default and requires `--apply` before writing. Future cleanup feedback should
include:

- the number of stale pinned servers and how often they occur;
- why `pin --stale` plus `pin --clear <server>` is too cumbersome;
- the dry-run output a bulk command should show before writing;
- confirmation that explicit `--apply` behavior would be acceptable.

## Redaction Rules

Never ask users to paste credential values. Keep only env var key names when
they are needed to reproduce config inference. Redact usernames, private paths,
private URLs, internal hostnames, customer names, workspace names, and
proprietary prompt/resource text before a fixture is committed.

Security-sensitive false negatives should use private disclosure in
`SECURITY.md` instead of a public issue.

## Done Criteria

A feedback item is closed when the new fixture fails before the fix, passes after
the fix, and the changelog explains any user-visible behavior change.
