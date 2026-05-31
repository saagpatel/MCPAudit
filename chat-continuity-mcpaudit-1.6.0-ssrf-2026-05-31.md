<model_recommendation>
Model: Opus 4.8 — next moves are open-ended (feature lane selection / brainstorm output); architecture/scoping judgment, not mechanical execution. Delegate implementation to Sonnet once a lane is chosen.
Extended thinking: ON for lane/idea selection; OFF for routine implementation.
</model_recommendation>

<context>
# Continuation: MCPAudit — post-1.6.0, calibration corpus hardened
# Carried over: 2026-05-31 (updated after PR #98 merged)
# Previous model: Opus 4.8 (Claude Code)
# State pointer: Read ~/.claude/projects/-Users-d/memory/last-session.md first.
# Cross-system: mcp__bridge-db__get_recent_activity(limit=20) — SHIPPED entries for v1.6.0 (SSRF) and PR #98 (calibration).

MCPAudit is a local-first MCP permission auditor (Python CLI, `mcp-permission-audit` on PyPI, repo github.com/saagpatel/MCPAudit). v1.6.0 (opt-in SSRF detection) is live on PyPI. The most recent work (PR #98) hardened the prompt/resource calibration corpus — test-only, no scanner/scoring change. The repo is in a clean stable-maintenance state. A brainstorm on future direction is the immediate next activity.
</context>

<decisions>
## Decisions made — do not revisit
- SSRF detection is additive + opt-in (`--ssrf-check`); never changes `risk_score.composite`/`non_tool_risk`; static/schema-derived. SARIF ids MCP011 (high)/MCP012 (med+low). Policy gate is opt-in `fail_on.ssrf` only (not under `fail_on.severity`).
- Calibration corpus (`tests/validation/non_tool_cases.json`) is the roadmap-blessed pre-req for any composite-scoring change ("observe before changing scoring"). Grow it; do NOT change the scorer formula until external field reports justify it.
- Non-tool score anchors use an exact `expected_non_tool_risk` field compared via `round(composite, 2)` in test_non_tool_calibration.py — FP-robust. Rounding lives ONLY in the test; scorer output is unchanged.
- Release mechanism: pushing a `vX.Y.Z` tag / publishing a GitHub release triggers publish.yml → OIDC trusted-publish to PyPI. No manual `uv publish`.
- PRs are squash-merged. Feature branches only; never commit to main.
</decisions>

<rejected>
## Rejected approaches
- OAuth 2.1 support: rejected — would require handling credential values, breaking the local-first/no-credential boundary.
- Rounding scorer OUTPUT to clean FP noise: out of scope — it's a user-visible output-contract change. Rounding stays in the test.
- Forcing a composite-scoring change now: blocked by roadmap until ≥2 external redacted field reports land (#83/#84 → #85).
- Bulk `git branch -D` of codex/* by the agent: blocked by the force-delete guardrail hook; operator runs it via `! git branch -D ...` (verified-safe, all 41 are squash remnants).
</rejected>

<pending_release>
## ⚠️ Pending release — do not forget
- main is at **1.7.0** (pyproject bumped, PR #99 merged) but **NOT tagged/published to PyPI**. Latest on PyPI is still 1.6.0.
- To release when ready: push a `v1.7.0` tag / publish a GitHub release → publish.yml fires OIDC trusted-publish to PyPI. CHANGELOG already has the [1.7.0] - 2026-05-31 section.
- Operator chose to hold the PyPI publish and batch it with future work.
</pending_release>

<current_state>
## Current state
- main @ commit 9cf4ce9 (PR #98 squashed), 0 ahead/0 behind origin. Working tree clean (only this continuity doc untracked).
- Version 1.6.0 LIVE on PyPI. GitHub release v1.6.0 is latest.
- PR #98 (merged): calibration corpus now exercises ALL 6 permission categories × ALL 7 injection patterns on prompt+resource targets. Added system_override/hidden_directive/unicode_direction coverage via 3 new server families (feature-flag-admin, support-macro-library, newsletter-composer). Added exact `non_tool_risk` composite anchors to all 14 expect-risk cases (closed the silent-score-halving hole). Refreshed docs/FEEDBACK-TO-FIXTURES.md.
- Full gate green: 353 pytest, ruff/mypy/format/uv-lock/git-diff clean, validate_patterns 100% (118/118). CI matrix 3.11/3.12/3.13 + CodeQL green on #98.
- Open issues: #83/#84 (collect external redacted field reports — BLOCKED on external humans, not code), #85 (convert reports→fixtures + beta decision, gated on #83/#84). No open PRs.
- Branch hygiene: 41 stale codex/* branches flagged for deletion (squash remnants, each 1 commit ahead, content verified in main). Deletion command handed to operator via `!`.
</current_state>

<in_progress>
## Work in progress
- Brainstorm on MCPAudit's next direction (this is the active activity — output may redefine next_steps).
- (Operator action) prune codex/* branches via `! git branch -D $(git for-each-ref --format='%(refname:short)' refs/heads/codex)`.
</in_progress>

<next_steps>
## Next steps — start here
1. BRAINSTORM OUTPUT lands here once the design dialogue completes. Until then, the standing lane options are below.
2. Roadmap-gated lanes (need external field reports first — see #83/#84/#85): allowlist-aware SSRF downgrade; fold prompt/resource non_tool_risk into composite scoring (docs/COMPOSITE-SCORING-PROPOSAL.md drafts this).
3. Always-actionable: keep growing the calibration corpus (new server families / new SSRF schemes ONLY with a redacted fixture justifying them); harden output contracts; doc/adoption-friction fixes.
4. For any new analyzer/detector module, run /code-review BEFORE committing (a prior session caught a critical camelCase false-negative TDD missed).
</next_steps>

<constraints>
## Constraints
- Read-only on MCP config files. Never store/log/transmit credential values — env var key names only.
- LLM analysis only behind `--llm-analysis`. Timeout-guard all server spawns. Platform-aware config paths.
- Additive only behind existing output contracts; semver-appropriate bump; CHANGELOG entry for user-visible changes; tests + docs.
- Conventional commits (no Co-Authored-By trailer), feature branch, squash-merge PRs.
</constraints>

<reference>
## Reference data
- Repo: /Users/d/Projects/MCPAudit · package: mcp-permission-audit · current version 1.6.0
- Verifier bar: `uv run pytest` ; `uv run ruff check` ; `uv run mypy .` ; `uv run ruff format --check` ; `uv lock --check` ; `git diff --check` ; `uv run python tests/validation/validate_patterns.py` ; `uv build`
- Calibration: tests/validation/non_tool_cases.json (16 cases) + tests/test_non_tool_calibration.py. Tool-permission recall corpus: tests/validation/servers/*.json (validate_patterns.py, 118/118).
- Injection patterns (7): ignore_instructions, system_override, prompt_leak, hidden_directive, unicode_direction, role_injection, credential_harvest. Categories (6): file_read, file_write, network, shell_execution, destructive, exfiltration.
- SSRF: rule ids MCP011 (high)/MCP012 (med/low). Flag `--ssrf-check`. Policy key `fail_on.ssrf`.
- Key files: src/mcp_audit/{ssrf,analyzer,injection,scorer,taxonomy,models,policy,sarif,report,server,cli}.py
- Release: publish.yml on `v*` tag → PyPI OIDC. CI: ci.yml (3.11/3.12/3.13) + codeql.yml.
- Recent PRs: #96/#97 (SSRF), #98 (calibration coverage + anchors). All squash-merged.
- Relevant memory: feedback_code_review_catches_camelcase.md.
</reference>
