# HANDOFF — MCPAudit

**Status:** v1.13.1 is live; launch/share-safe packet is merged on `main`; launch-day runbook is ready.
**Branch:** `main` after the launch-packet, preview-asset, connected hero GIF, SARIF proof, policy-gate demo, and launch-day runbook refresh. Tag `v1.13.1` remains the latest release tag.
**Latest on PyPI:** `1.13.1` (verified live: JSON API + simple index + refreshed `uvx` install).

## Completed this session
- **1.13.0 shipped** — `scan --redact` field-report mode:
  scrubs hostname, home-path usernames, and server names from `--json`/`--sarif`/`--html`
  artifacts so config-only reports are safer to share publicly. (#121)
- **1.13.0 docs follow-up** — README, external request packet, outreach copy, and Show HN
  draft now include `--redact` in the canonical field-report command. (#122)
- **1.13.1 release prep** — patch release intended to refresh PyPI package metadata/README
  so the public package page also shows the `--redact` field-report command.
- **1.13.1 released** — tag `v1.13.1` triggered publish.yml OIDC; PyPI now serves the
  corrected README/long description with the `--redact` field-report command.
- **Launch/share-safe packet merged** — README now leads with badges, the "Audit what your AI
  agents can actually touch" hook, a 60-second start, a zero-touch public-fixture preview image,
  and safe field-report guidance. Launch posts, Show HN draft, demo asset plan, and issue-template
  regression coverage are aligned around `--redact`.
- **Launch-day runbook added** — `docs/LAUNCH-DAY-RUNBOOK.md` captures the exact HN URL/title,
  Tuesday/Wednesday launch window, first-comment timing, response routing, and field-report
  acceptance checks.
- **Launch response playbook added** — `docs/LAUNCH-RESPONSE-PLAYBOOK.md` captures live reply
  snippets, first-4-hour triage order, hostile-thread posture, and first-day evidence capture.
- **Launch control card added** — `docs/LAUNCH-CONTROL-CARD.md` is the single-screen
  operator card for HN submit fields, open tabs, final go checks, first 5 minutes,
  and explicit do-not-do guardrails.
- **Launch preflight added** — `scripts/launch_preflight.py` checks launch docs,
  assets, local git alignment, current-head GitHub CI/Self Audit/CodeQL status, and
  public README / asset URLs plus PyPI / `uvx` package availability. Use
  `python scripts/launch_preflight.py --print-hn-copy` on launch morning to print
  the exact HN URL, title, and first comment after checks pass.
- **Hero/proof assets landed** — README now includes the connected public-fixture GIF
  `docs/assets/hero-scan.gif`, zero-touch preview
  `docs/assets/mcp-audit-config-only-scan.png`, and SARIF/code-scanning proof
  `docs/assets/ci-sarif.png`.
- **Policy-gate launch asset landed** — README and `DEMO-ASSETS.md` now include the
  strict policy-gate GIF path, with a scoped VHS tape/helper and regression coverage
  proving the public fixture exits `2` under `examples/policies/ci-strict.yaml`.
- **HTML report launch asset landed** — README and `DEMO-ASSETS.md` now include
  `docs/assets/html-report.png`, a redacted static preview of the self-contained
  HTML report path.
- **SARIF relative config paths fixed** — SARIF output now handles relative config paths cleanly,
  with regression coverage.
- **1.12.0 field-scan evidence remains current historical evidence** — popular public
  server sample config + solo evidence show MCP025/MCP026 package verification worked
  against real npm/PyPI packages; it still does not replace external reports. (#117)

## Key Decisions
- `--redact` is opt-in and only affects file artifacts; terminal output keeps local values
  readable for the operator.
- Field-report docs should lead with `scan --skip-connect --json mcp-audit-field-report.json --redact`.
  The checklist stays the backstop for credential values and proprietary prompt/tool/schema text.
- Do not claim beta: issues #83/#84/#85 still require two accepted external redacted reports.
- Keep `risk_score.composite` unchanged unless repeatable external fixture evidence justifies it.

## In Progress / Blocked
- No release blocker. `main` is clean and remote checks are green.
- External beta evidence is still the gating item: issues #83/#84/#85 need two accepted external
  redacted, config-only field reports.

## Next Steps
- Recruit two external reporters via `docs/EXTERNAL-FIELD-REPORT-REQUEST.md` / Show HN draft,
  then triage #83/#84/#85.

## Verification
- `uv run pytest` passed (591 tests).
- `uv run ruff check` passed.
- `uv run mypy .` passed.
- `uv lock --check` passed.
- `uv build --clear` passed.
- Built wheel metadata is `Version: 1.13.1` and includes the `--redact` field-report command.
- Built sdist includes `version = "1.13.1"` and the `--redact` field-report command.
- GitHub publish workflow for `v1.13.1` passed.
- PyPI JSON reports latest `1.13.1` with two files.
- PyPI simple index lists the `1.13.1` wheel and sdist.
- PyPI long description contains `mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact`.
- `uvx --refresh-package mcp-permission-audit --from mcp-permission-audit==1.13.1 mcp-audit --version`
  reports `mcp-audit, version 1.13.1`.
- GitHub `main` checks are green for CI, Self Audit, and CodeQL on `a60a06c`.
- Share-safe packet smoke pass confirmed README, launch posts, Show HN draft, external outreach,
  field-report docs, trust packet, demo asset plan, and local preview image keep the public
  field-report path on `--skip-connect --json ... --redact`.
- `git diff --check` passed.

## Files Changed
- Release-packet refresh expected files:
  `HANDOFF.md`, `.github/ISSUE_TEMPLATE/field_report.md`, `docs/FIELD-REPORTS.md`,
  `docs/FEEDBACK-TO-FIXTURES.md`, `AGENTS.md`, `CLAUDE.md`, `.pre-commit-hooks.yaml`,
  and `tests/test_issue_templates.py`.
- Launch/share-safe packet files:
  `README.md`, `launch-posts.md`, `DEMO-ASSETS.md`, `docs/SHOW-HN-DRAFT.md`,
  `docs/LAUNCH-CONTROL-CARD.md`, `docs/LAUNCH-DAY-RUNBOOK.md`,
  `docs/LAUNCH-RESPONSE-PLAYBOOK.md`,
  `docs/assets/mcp-audit-config-only-scan.png`,
  `docs/assets/hero-demo-config.json`, `docs/assets/hero.tape`,
  `docs/assets/hero-scan.gif`, `docs/assets/ci-sarif.png`,
  `docs/assets/html-report.png`,
  `scripts/launch_preflight.py`, `src/mcp_audit/sarif.py`, and `tests/test_sarif.py`.

## Gotcha
- `scan --config-only` means "only this config file" — it does NOT skip connection. Add
  `--skip-connect` to avoid spawning servers.
- This refresh is docs/package metadata only; no scanner behavior or output contract changes.
