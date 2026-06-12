# mcp-audit Egress Bundle (D3 + D1)

## Overview
Feature addition to the existing `MCPAudit` repo (`/Users/d/Projects/MCPAudit`): a
destination-aware egress detector plus a trusted-destination residual (the January 2026 Claude
Cowork lesson) for mcp-audit. It audits *where* each MCP server may send data — not just whether
it can exfiltrate. Static-only, opt-in, additive. **Read the existing modules first** and follow
their patterns.

## Tech Stack
- Python 3.12+ — matches the repo `.python-version`
- `urllib.parse` (stdlib) — reuse `ssrf.py` host primitives, do not reimplement
- `pyyaml` — existing; policy + examples parsing
- `pytest` via `uv run pytest` — existing test runner

## Development Conventions
- Static analysis only: never make a network call; never read credential values
- Additive + opt-in: behind `--egress-check`; default output and existing policy files unchanged
- Reuse, don't reimplement: consume `ssrf.py` fixed-host/allowlist helpers as the single destination source
- Match existing patterns: finding dataclass like `SsrfFinding`/`TrifectaFinding`; gate like `fail_on.ssrf`
- Python: type hints, frozen dataclasses, exact-token matching (no substring); tests before commit

## Current Phase
**Phase 0: Foundation — model + taxonomy + detector core**
See IMPLEMENTATION-ROADMAP.md for full phase details.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Residual logic home | new `egress.py` consumes `ssrf` findings + allowlist | keeps SSRF semantics stable; one module owns new behavior |
| Multi-tenant host source | curated default constant, config-extensible | no ecosystem registry exists; conservative default |
| Finding model | new `EgressFinding` + `EgressKind` in `models.py` | matches `SsrfFinding`/`TrifectaFinding`/`DriftFinding` pattern |
| Residual severity | LOW/MEDIUM, never HIGH | advisory; bounds false-positive blast radius |
| CLI surface | `--egress-check` (opt-in, like `--trifecta-check`) | consistency with existing detector flags |
| Backward compat | new policy keys optional, default off | existing policy files keep parsing |

## Phase-Boundary Review
At the end of every phase, run `/ultrareview` before committing the phase-final code. Do not
skip on phases that "feel small."

## Do NOT
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md.
- Do not make network calls or read/log/store credential values — static analysis only; credential signals are param-name / userinfo-template only.
- Do not mutate `ssrf.py` suppression semantics — `egress.py` re-derives the residual (downgrade-not-suppress); `ssrf` tests must stay green.
- Do not break existing policy files — `fail_on.egress` and `egress_allowlist` are optional and default off.
