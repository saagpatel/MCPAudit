# mcp-audit Rule of Two Posture (D2)

## Overview
Feature addition to the existing `MCPAudit` repo (`/Users/d/Projects/MCPAudit`): enrich the
trifecta detector so every finding carries a Rule of Two remediation — which leg to drop and the
concrete action (Meta's Oct 2025 framework). **Read `src/mcp_audit/trifecta.py` first.**
Static-only, additive, advisory.

## Tech Stack
- Python 3.12+ — matches the repo `.python-version`
- stdlib only — no parsing/network; reuse the existing leg model in `trifecta.py`
- `pytest` via `uv run pytest` — existing runner

## Development Conventions
- Static analysis only: no network calls, no new inference (matches the `trifecta.py` header)
- Additive: never change *when* the trifecta fires — only enrich the finding
- Advisory only: no auto-remediation, no config mutation, no finding suppression
- Match existing patterns: posture is a field on `TrifectaFinding`, read by renderers like any other attribute
- Python: type hints, frozen dataclasses; tests before commit

## Current Phase
**Phase 0: Foundation — model + posture computation**
See IMPLEMENTATION-ROADMAP.md for full phase details.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Posture home | `rule_of_two` field on `TrifectaFinding`, computed in `TrifectaAnalyzer` | finding-centric; renderers read it like any attribute |
| Leg-to-drop heuristic | prefer Leg 3 (restrict egress) > leg with fewest contributing tools | lowest functionality loss; Leg 3 enforceable via the egress detector |
| Recommendation shape | one primary + two listed alternatives | actionable without being prescriptive-only |
| Enforcement | none new — `fail_on.trifecta` already gates | posture is advisory remediation, not a gate |

## Phase-Boundary Review
At the end of every phase, run `/ultrareview` before committing the phase-final code. Do not
skip on phases that "feel small."

## Do NOT
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md.
- Do not change *when* the trifecta fires — the posture only enriches an already-fired finding.
- Do not make network calls, mutate config, or suppress findings — the posture is advisory and static-only.
- Do not hard-depend on the egress detector — phrase the Leg 3 action generically and reference `--egress-check` only when present.
