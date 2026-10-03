# mcp-audit Rule of Two Posture (D2)

## Overview
Feature addition to the existing `MCPAudit` repo (repository root): enrich the
trifecta detector so every finding carries a Rule of Two remediation — which leg to drop and the
concrete action (Meta's Oct 2025 framework). **Read `src/mcp_audit/trifecta.py` first.**
Static-only, additive, advisory.

## Tech Stack
- Python 3.11+ — matches the repo `.python-version`
- no new dependencies — no parsing/network; reuse the existing leg model in `trifecta.py`
- `pytest` via `uv run pytest` — existing runner

## Development Conventions
- Static analysis only: no network calls, no new inference (matches the `trifecta.py` header)
- Additive: never change *when* the trifecta fires — only enrich the finding
- Advisory only: no auto-remediation, no config mutation, no finding suppression
- Match existing patterns: posture is a field on `TrifectaFinding`, read by renderers like any other attribute
- Python: type hints, Pydantic models; tests before commit

## Current Phase
**Model, posture computation, and text/HTML/SARIF rendering are implemented.**
See IMPLEMENTATION-ROADMAP.md for the original phase details.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Posture home | `rule_of_two` field on `TrifectaFinding`, computed in `TrifectaAnalyzer` | finding-centric; renderers read it like any attribute |
| Leg-to-drop heuristic | prefer Leg 3 (restrict egress) > leg with fewest contributing tools | lowest functionality loss; Leg 3 is checkable via the egress detector and gateable with `fail_on.egress` |
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
