# HANDOFF — MCPAudit egress bundle + rule of two

Branch: `feat/egress-detector` (off `main`). All work additive; existing detectors untouched.

## Deliverable 1 — Egress Bundle (D3 + D1): ✅ COMPLETE

A static, opt-in egress detector that audits *where* an MCP server may send data,
complementing SSRF's "can a caller steer the destination?".

| Phase | Commit | Scope |
|-------|--------|-------|
| 0 | `cae5c8a` | EgressFinding model + EgressKind/Severity + taxonomy (MCP040–042) + detector core (unbounded HIGH, outside-allowlist MEDIUM). Extracted `ssrf.fixed_host_from_uri` (behavior-neutral). |
| 1 | `199546a` | D1 trusted-destination residual (Cowork lesson): MULTI_TENANT_API_HOSTS + credential-bearing detection → TRUSTED_DESTINATION_RESIDUAL (LOW/MEDIUM, never HIGH), downgrade-not-suppress. |
| 2 | `8305866` | `fail_on.egress` policy gate (opt-in, mirrors SSRF) + `egress_allowlist`/`multi_tenant_hosts` config keys (global + per-server) + examples/policies/egress.yaml. |
| 3 | `fcfffa4` | `--egress-check`/`--egress-allowlist`/`--multi-tenant-hosts` CLI; report/HTML/SARIF rendering; docs/EGRESS-DETECTION.md + README + CHANGELOG; test_egress_integration.py. |

### Verification (as of Phase 3)
- `uv run pytest -q` → **620 passed**, zero regressions (was 585 at session start; +35).
- `uv run mypy src/ --strict` → clean (37 files). NOTE: repo type-checker is **mypy**, not pyright (Makefile `typecheck`).
- `uv run ruff check` + `ruff format --check` → clean.
- Per-phase `/code-review` (independent subagent auditors): one real defect found+fixed in Phase 1 (`_is_remote_uri` scheme-gate asymmetry), all other phases clean. Phase 3 CLI "critical" finding was a verified false positive (Click binds command params by name, not positionally).

### Key design decisions
- EgressFinding is a Pydantic BaseModel (matches SsrfFinding), NOT the roadmap's dataclass sketch — disk wins. rule_id/title/description/remediation all computed from `egress_metadata(kind)`.
- Empty allowlist trusts nothing → every fixed external destination flagged (operator-confirmed).
- `--egress-check` includes SSRF analysis (egress consumes the caller-controlled signal); SSRF Warnings section appears alongside Egress.
- Policy `egress_allowlist`/`multi_tenant_hosts` merge with CLI flags via `_merge_host_args` (policy loaded up front in `_run_scan`).

## Deliverable 2 — Rule of Two Posture (D2): ⏳ NOT STARTED

Roadmap: `docs/handoffs/rule-of-two/IMPLEMENTATION-ROADMAP.md`. Enrich every fired
TrifectaFinding with a RuleOfTwoPosture (advisory; never changes when the trifecta fires).
- Phase 0: RuleOfTwoPosture model + `_compute_rule_of_two()` + attach at both fire sites
  (analyze_server, analyze_fleet). Leg-drop heuristic: prefer Leg 3, else fewest-tools leg.
- Phase 1: render in report/HTML/SARIF + TRIFECTA-DETECTION.md + CHANGELOG.

## Not done / follow-ups
- Branch not merged to main, not pushed (per contract — push only when asked).
- Rule of Two deliverable pending.
