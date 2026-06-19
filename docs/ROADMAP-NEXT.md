# MCPAudit Next Roadmap

MCPAudit `2.1.0` is a stable public package line with config-health findings,
policy gates, prompt/resource non-tool risk reporting, reviewed stale pin
cleanup, detector coverage, SARIF/JSON/HTML outputs, redacted field-report
fixtures, and consumer-contract tests across the checked-in Python, Node, and
dashboard examples. The field-report intake path has a dedicated public issue
template. The next line should collect external reports before using a beta
label or changing scoring semantics.

Tracked `1.5` evidence-intake work lives in `docs/1.5-EVIDENCE-INTAKE.md`,
with the release decision in `docs/1.5-RELEASE-DECISION.md`.
Beta-readiness evidence lives in `docs/BETA-READINESS-EVIDENCE.md`.
Field-report evidence lives in `docs/FIELD-REPORTS.md`.
External beta-evidence tracking lives in
<https://github.com/saagpatel/MCPAudit/milestone/4>.
The contributor request packet lives in
`docs/EXTERNAL-FIELD-REPORT-REQUEST.md`.

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

## 5. Beta Readiness

Status: stable pre-beta in `2.1.0`; external evidence still open.

Shipped through `1.5.1`:

- output-contract upgrade compatibility tests for older report shapes;
- tolerance test for future additive report fields;
- config-only evidence notes from real local MCP setup shapes;
- release decision to ship `1.5.1` polish rather than `1.6.0` beta prep.

Shipped through `1.5.2`:

- redacted field-report fixtures for mixed, single-client, and quiet
  config-only setup shapes;
- consumer-contract coverage that runs the Python parser, Node parser, and
  dashboard summary examples against compatibility and field-report fixtures;
- field-report evidence docs that track the current milestone, GitHub issues,
  and release decision to ship `1.5.2` polish rather than `1.6.0` beta prep.

Shipped through `1.5.3`:

- dedicated public field-report issue template for config-only external
  evidence;
- expanded field-report intake docs, fixture acceptance bar, and beta-readiness
  decision notes;
- tests that keep the public template and docs aligned with the external
  redacted-report blocker.

Shipped through `1.5.4`:

- external field-evidence milestone and tracking issues for the two required
  reports plus fixture conversion and beta decision;
- docs and tests that keep that milestone visible until the external evidence
  blocker is resolved.

Shipped through `1.5.5`:

- copy-paste external field-report request packet for contributors;
- maintainer triage checklist for turning external reports into fixtures or a
  no-code beta decision;
- issue comments that point #83, #84, and #85 at the request packet.

Current follow-ups:

- collect the first external redacted report:
  <https://github.com/saagpatel/MCPAudit/issues/83>;
- collect the second external redacted report:
  <https://github.com/saagpatel/MCPAudit/issues/84>;
- turn accepted external report friction into fixtures and make the beta
  decision: <https://github.com/saagpatel/MCPAudit/issues/85>.

## 6. SSRF Detection

Status: shipped in `1.6.0`.

`scan --ssrf-check` flags tools and resources whose interface lets a caller steer
a server-side request target (URL/host parameters paired with fetch verbs;
caller-templated remote resource hosts). Static and schema-derived: no request is
issued and no credential value is read. Findings are additive (`ssrf_findings`),
opt-in, carry stable SARIF rule IDs `MCP011`/`MCP012`, and gate only through the
dedicated `fail_on.ssrf` policy key. Calibrated against the real-world validation
corpus: flags `fetch`, `git_clone`, and headless-browser `navigate` tools while
leaving plain network and search tools unflagged. See `docs/SSRF-DETECTION.md`.

Candidate follow-ups:

- extend resource SSRF coverage to additional remote schemes only when a redacted
  real-world fixture justifies it;
- consider an allowlist-aware downgrade once field reports show benign internal
  fetch tools producing noise.

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
