# HANDOFF — MCPAudit

**Status:** Preparing v1.13.1 package-metadata refresh so PyPI shows the safe field-report ask.
**Branch:** `main` @ `e3f7df7` before local release edits. No stale branches.
**Latest on PyPI:** `1.13.0` before this refresh (1.13.1 not yet published).

## Completed this session
- **1.13.0 shipped** — `scan --redact` field-report mode:
  scrubs hostname, home-path usernames, and server names from `--json`/`--sarif`/`--html`
  artifacts so config-only reports are safer to share publicly. (#121)
- **1.13.0 docs follow-up** — README, external request packet, outreach copy, and Show HN
  draft now include `--redact` in the canonical field-report command. (#122)
- **1.13.1 release prep** — patch release intended to refresh PyPI package metadata/README
  so the public package page also shows the `--redact` field-report command.
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
- Publish/tag v1.13.1, then verify PyPI JSON/simple index and rendered README show
  the `--redact` field-report command.
- Recruit two external reporters via `docs/EXTERNAL-FIELD-REPORT-REQUEST.md` / Show HN draft,
  then triage #83/#84/#85.

## Verification
- `uv run pytest` passed (586 tests).
- `uv run ruff check` passed.
- `uv run mypy .` passed.
- `uv lock --check` passed.
- `uv build --clear` passed.
- Built wheel metadata is `Version: 1.13.1` and includes the `--redact` field-report command.
- Built sdist includes `version = "1.13.1"` and the `--redact` field-report command.
- `git diff --check` passed.

## Files Changed
- Release-packet refresh expected files:
  `HANDOFF.md`, `.github/ISSUE_TEMPLATE/field_report.md`, `docs/FIELD-REPORTS.md`,
  `docs/FEEDBACK-TO-FIXTURES.md`, `AGENTS.md`, `CLAUDE.md`, `.pre-commit-hooks.yaml`,
  and `tests/test_issue_templates.py`.

## Gotcha
- `scan --config-only` means "only this config file" — it does NOT skip connection. Add
  `--skip-connect` to avoid spawning servers.
- This refresh is docs/package metadata only; no scanner behavior or output contract changes.
