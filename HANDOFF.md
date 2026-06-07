# HANDOFF — MCPAudit

**Status:** v1.13.0 is released and live. Current local work is a release-packet/docs refresh.
**Branch:** `main` @ `7945cf4` (in sync with origin before local docs edits). No stale branches.
**Latest on PyPI:** `1.13.0` (verified live: JSON API + simple index; wheel + sdist present).

## Completed this session
- **1.13.0 shipped** — `scan --redact` field-report mode:
  scrubs hostname, home-path usernames, and server names from `--json`/`--sarif`/`--html`
  artifacts so config-only reports are safer to share publicly. (#121)
- **1.13.0 docs follow-up** — README, external request packet, outreach copy, and Show HN
  draft now include `--redact` in the canonical field-report command. (#122)
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
- Current local refresh updates the handoff, field-report template/docs, current-state notes,
  and doc tests so the share packet consistently points contributors at `--redact`.

## Next Steps
- If publishing a share packet externally, note that PyPI 1.13.0's rendered README was built
  from the tag before #122; GitHub `main` has the safer `--redact` ask.
- Recruit two external reporters via `docs/EXTERNAL-FIELD-REPORT-REQUEST.md` / Show HN draft,
  then triage #83/#84/#85.

## Verification
- `uv run pytest tests/test_issue_templates.py` passed.
- `uv run pytest` passed (586 tests).
- `uv run ruff check` passed.
- `uv run mypy .` passed.
- `git diff --check` passed.

## Files Changed
- Release-packet refresh expected files:
  `HANDOFF.md`, `.github/ISSUE_TEMPLATE/field_report.md`, `docs/FIELD-REPORTS.md`,
  `docs/FEEDBACK-TO-FIXTURES.md`, `AGENTS.md`, `CLAUDE.md`, `.pre-commit-hooks.yaml`,
  and `tests/test_issue_templates.py`.

## Gotcha
- `scan --config-only` means "only this config file" — it does NOT skip connection. Add
  `--skip-connect` to avoid spawning servers.
- PyPI package version is live at `1.13.0`, but PyPI's long description may lag the post-tag
  README docs fix until the next publish/metadata refresh path.
