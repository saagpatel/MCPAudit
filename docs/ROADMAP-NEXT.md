# MCPAudit Next Roadmap

MCPAudit `1.4.2` is published with structured config-health findings, policy
gates, prompt/resource non-tool risk reporting, pin maintenance helpers, and
copy-pasteable adoption examples. The next line should collect real-world
evidence before changing scoring semantics or adding broader pin cleanup writes.

## 1. Config Health Depth

Status: in progress.

Add fixture-backed diagnostics only when they can be detected from local MCP
configuration without connecting to servers or reading credential values.

Shipped through `1.4.2`:

- missing local command paths for stdio servers;
- server names that conflict across global and project scopes;
- package-runner source review for commands such as `npx`, `uvx`, and `docker`;
- conflicting server definitions when the same server name points at different
  commands or URLs;
- clearer remediation for intentional project-local shadowing.

Candidate follow-ups:

- add new config-health diagnostics only when real feedback provides a small
  redacted fixture.

## 2. Adoption Examples

Status: in progress.

Keep examples copy-pasteable and conservative. Examples should start with
`--skip-connect` when the goal is config-health review, then graduate to
connected scans only after the server set is understood.

Shipped through `1.4.2`:

- GitHub Actions config-health policy gate example;
- Python and Node JSON consumers that summarize config-health findings by
  severity per server;
- dashboard-oriented JSON consumer summary for CI status pages.

- dashboard status-page style fixture coverage for mixed config-health,
  non-tool risk, policy, and failed-connection signals.

Candidate follow-ups:

- organization-specific policy profiles only when repeated user patterns justify
  them.
- track dashboard consumer needs in
  <https://github.com/saagpatel/MCPAudit/issues/59>.

## 3. Pin Maintenance UX

Status: hold writes explicit.

Keep `pin --stale` read-only and keep cleanup server-scoped through
`pin --clear <server>`. Bulk stale cleanup remains intentionally out of scope
until users show a repeated need for it.

Tracking issue: <https://github.com/saagpatel/MCPAudit/issues/60>.

## 4. Prompt And Resource Scoring

Status: observe before changing scoring.

Prompt/resource findings stay visible, policy-gatable, and summarized through
`non_tool_risk`. Do not merge them into `risk_score.composite` until more
real-world fixtures prove a stable scoring model.

Shipped through `1.4.2`:

- GitHub issue, PostgreSQL analytics, and Slack thread fixtures for
  prompt/resource calibration.

- calendar, container registry, and vault-style prompt/resource fixtures plus a
  benign glossary case.

Tracking issue before any composite scoring change:
<https://github.com/saagpatel/MCPAudit/issues/61>.

## Verification Bar

Before the next release, run:

```bash
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
uv lock --check
git diff --check
uv run python tests/validation/validate_patterns.py
uv build --clear
```
