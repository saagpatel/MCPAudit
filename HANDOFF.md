# HANDOFF — MCPAudit

**Status:** Complete + one open release gap. main is at **v1.7.0**; **PyPI is still at 1.6.0**.
**Branch:** main (0 ahead / 0 behind origin) · **pyproject version:** 1.7.0 · **HEAD:** 6606fe9 (PR #99)

## ⚠️ Top next-session action — release gap
- main + `pyproject.toml` are at **1.7.0** (PR #99 trifecta merged), but **no `v1.7.0` git tag
  exists** and the latest GitHub release / PyPI version is **1.6.0**. The tag-triggered
  `publish.yml` never fired for 1.7.0.
- To ship 1.7.0: confirm CHANGELOG has a 1.7.0 entry, then **publish a `v1.7.0` GitHub release**
  (or push the `v1.7.0` tag) → `publish.yml` OIDC publishes to PyPI.
- **Verify the publish via the PyPI *simple* index** (`pypi.org/simple/mcp-permission-audit/`) +
  the `publish.yml` per-step status — the JSON endpoint cache-lags. Log SHIPPED only after.

## Completed
- **This conversation:** merged Dependabot #94 (idna 3.15); built + released **v1.6.0 opt-in SSRF
  detection** (`--ssrf-check`, MCP011/MCP012; PRs #96, #97); verified **1.6.0 live on PyPI**.
  `/code-review` caught a critical camelCase tokenization false-negative pre-merge.
- **Parallel sessions (not this conversation), already merged to main:**
  - **PR #98** — full injection-pattern calibration coverage + exact `non_tool_risk` composite anchors
    (test-only: docs/FEEDBACK-TO-FIXTURES.md, tests/test_non_tool_calibration.py, non_tool_cases.json).
  - **PR #99** — **fleet-aware lethal-trifecta detection** (`--trifecta-check`, rules MCP013/MCP014),
    version bumped to **1.7.0**. New: src/mcp_audit/trifecta.py, tests/test_trifecta*.py,
    examples/policies/trifecta-aware-ci.yaml, docs/TRIFECTA-DETECTION.md.

## In Progress / Next Steps
1. **Ship v1.7.0** (see release-gap block above) — highest priority; the work is merged but unreleased.
2. Roadmap-gated lanes (need external field reports #83/#84 → #85): allowlist-aware SSRF downgrade;
   fold non_tool_risk into composite scoring (docs/COMPOSITE-SCORING-PROPOSAL.md).
3. Always-actionable: grow calibration corpus (new schemes/families only with a redacted fixture).
4. New analyzer/detector module → run `/code-review` BEFORE committing.

## Blocked
- #83/#84 (external redacted field reports) — blocked on external humans, not code.

## Key Decisions
- SSRF + trifecta detection are additive + opt-in (`--ssrf-check` / `--trifecta-check`); dedicated
  opt-in policy gates, NOT under the broad `fail_on.severity` shortcut.
- Release = publish `vX.Y.Z` GitHub release / push tag → `publish.yml` OIDC → PyPI. No manual `uv publish`.
- Feature branches + squash-merge only; never commit to main.

## Verify bar (all green on main right now)
`uv run pytest` (**397**) · `ruff check` · `ruff format --check` · `mypy .` · `uv lock --check`
· `git diff --check` · `python tests/validation/validate_patterns.py` (118/118) · `uv build`

## Files Changed (this session's SSRF work; #98/#99 landed separately)
src/mcp_audit/{ssrf,cli,models,policy,report,sarif,server,taxonomy}.py · tests/test_ssrf*.py ·
examples/policies/{ssrf-aware-ci.yaml,README.md} · docs/{SSRF-DETECTION,OUTPUT-CONTRACT,ROADMAP-NEXT}.md
· README · CHANGELOG · pyproject

## Uncommitted (untracked, disposable)
- `HANDOFF.md` (this file) · `chat-continuity-mcpaudit-1.6.0-ssrf-2026-05-31.md`
