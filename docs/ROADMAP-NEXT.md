# MCPAudit Next Roadmap

MCPAudit `1.5.0` is prepared with structured config-health findings, policy
gates, prompt/resource non-tool risk reporting, reviewed stale pin cleanup,
dashboard-consumer improvements, copy-pasteable adoption examples, adoption
smoke coverage, redacted config-health fixtures, and expanded prompt/resource
scoring evidence. The next line should collect external reports before changing
scoring semantics.

Tracked `1.5` evidence-intake work lives in `docs/1.5-EVIDENCE-INTAKE.md`,
with the release decision in `docs/1.5-RELEASE-DECISION.md`.

## 1. Config Health Depth

Status: in progress.

Add fixture-backed diagnostics only when they can be detected from local MCP
configuration without connecting to servers or reading credential values.

Shipped through `1.5.0`:

- missing local command paths for stdio servers;
- server names that conflict across global and project scopes;
- package-runner source review for commands such as `npx`, `uvx`, and `docker`;
- conflicting server definitions when the same server name points at different
  commands or URLs;
- clearer remediation for intentional project-local shadowing.
- redacted fixture coverage for local shadowing, remote credential headers, and
  shell-wrapped remote URL arguments.

Candidate follow-ups:

- add new config-health diagnostics only when real feedback provides a small
  redacted fixture.
- keep synthetic redacted config-health fixtures close to the current scanner
  behavior so new diagnostics can be compared against known setup patterns.

## 2. Adoption Examples

Status: in progress.

Keep examples copy-pasteable and conservative. Examples should start with
`--skip-connect` when the goal is config-health review, then graduate to
connected scans only after the server set is understood.

Shipped through `1.5.0`:

- GitHub Actions config-health policy gate example;
- Python and Node JSON consumers that summarize config-health findings by
  severity per server;
- dashboard-oriented JSON consumer summary for CI status pages.
- dashboard status-page style fixture coverage for mixed config-health,
  non-tool risk, policy, and failed-connection signals.
- dashboard summary fields for status counts, max risk, policy failures, and
  attention rows.
- smoke coverage for docs, CI examples, policy artifacts, and milestone links.

Candidate follow-ups:

- organization-specific policy profiles only when repeated user patterns justify
  them.
- organization-specific dashboard profiles only when repeated user patterns
  justify them.
- keep smoke tests on docs and examples so copy-paste adoption paths stay
  installable and report-producing.

## 3. Pin Maintenance UX

Status: shipped explicit bulk cleanup.

Keep `pin --stale` read-only and keep cleanup server-scoped through
`pin --clear <server>`. `pin --clear-stale` now previews bulk stale cleanup and
requires `--apply` before writing.

Completed issue: <https://github.com/saagpatel/MCPAudit/issues/60>.

## 4. Prompt And Resource Scoring

Status: observe before changing scoring.

Prompt/resource findings stay visible, policy-gatable, and summarized through
`non_tool_risk`. Do not merge them into `risk_score.composite` until more
real-world fixtures prove a stable scoring model.

Shipped through `1.5.0`:

- GitHub issue, PostgreSQL analytics, and Slack thread fixtures for
  prompt/resource calibration.
- calendar, container registry, and vault-style prompt/resource fixtures plus a
  benign glossary case.
- documented combined-score proposal that keeps `risk_score.composite`
  unchanged.
- issue tracker, browser automation, and resource-only injection evidence.
- release decision to ship `1.5.0` as adoption hardening instead of beta.

Completed fixture/proposal issue:
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
