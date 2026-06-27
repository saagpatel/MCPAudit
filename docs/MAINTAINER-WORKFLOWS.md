# Maintainer Workflows

This project uses Codex as a maintainer aid for review, triage, and release
preparation. Codex does not replace local tests, GitHub checks, or maintainer
judgment; every change should still be grounded in repo evidence and reviewed
before release.

Good Codex tasks for MCPAudit:

- turn redacted field reports into small fixtures and regression tests;
- review detector changes for false-positive risk, output-contract drift, and
  secret-handling regressions;
- inspect GitHub Actions failures, CodeQL alerts, and dependency update PRs;
- prepare release-readiness checks without publishing, tagging, or uploading;
- compare README, security docs, and output-contract docs against implemented
  behavior before public application or release work.

Keep Codex runs conservative around security-sensitive surfaces:

- do not read credential-bearing local configs, raw logs, cookies, keychains, or
  private transcripts;
- prefer `mcp-audit scan --skip-connect` fixtures before connected scans;
- never invent adoption, user counts, external validation, or benchmark claims;
- treat code-scanning alerts as work items to fix, dismiss with evidence, or
  document as intentional test/demo fixtures.
