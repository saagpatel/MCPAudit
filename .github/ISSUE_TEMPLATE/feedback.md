---
name: MCPAudit feedback
about: Share MCPAudit false positives, missing detections, or adoption friction
title: "[feedback] "
labels: feedback
assignees: ''
---

## Feedback type

- [ ] False positive
- [ ] False negative / missing detection
- [ ] Policy gate request
- [ ] SARIF or JSON output issue
- [ ] Pinning or drift workflow issue
- [ ] Documentation or adoption friction
- [ ] Prompt/resource scoring fixture
- [ ] Dashboard JSON consumer friction
- [ ] Bulk stale-pin cleanup request
- [ ] Other

## Reproduction mode

- [ ] `scan --skip-connect`
- [ ] connected `scan`
- [ ] `scan --inject-check`
- [ ] `scan --pin-check`
- [ ] `scan --policy`
- [ ] `pin --status`, `pin --refresh`, or `pin --stale`
- [ ] JSON or SARIF consumer parsing
- [ ] Dashboard or CI status-page integration
- [ ] Not sure

## MCPAudit version

```bash
mcp-audit --version
```

## What happened?

Describe what you ran and what MCPAudit reported.

```bash
mcp-audit ...
```

## What would have been more useful?

Describe the expected finding, output shape, policy behavior, or documentation
path.

## Expected regression assertion

If this became a test fixture, what should the test prove?

- [ ] A finding should be present
- [ ] A finding should not be present
- [ ] Severity, category, rule ID, or target metadata should change
- [ ] JSON/SARIF output shape should stay compatible
- [ ] Policy pass/fail behavior should change
- [ ] Pin drift or stale-pin behavior should change
- [ ] Prompt/resource `non_tool_risk` behavior should change
- [ ] Dashboard summary behavior should change

## Minimal redacted fixture

Paste redacted MCP config, tool metadata, prompt/resource metadata, or
report snippets. Smaller examples are easier to turn into regression tests.

Do not include:

- API keys, tokens, passwords, cookies, or credential values
- private file paths or usernames
- internal hostnames, private URLs, customer names, or workspace names
- proprietary prompt, resource, tool, or schema text that cannot be public

## Fixture permission

- [ ] I am comfortable with a redacted version of this example becoming a public
      fixture.
- [ ] This report may need private triage first.

If this involves a security-sensitive false negative, use private disclosure in
`SECURITY.md` instead of a public issue.
