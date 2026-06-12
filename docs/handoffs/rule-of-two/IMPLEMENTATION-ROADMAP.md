# mcp-audit Rule of Two Posture (D2) — Implementation Roadmap

Feature addition to the existing `MCPAudit` repo at `/Users/d/Projects/MCPAudit`
(`src/mcp_audit/trifecta.py`). **Not greenfield** — it enriches the existing trifecta detector.
Read `trifecta.py` first; reuse its leg model (`_LEG1_CATEGORIES`, ingestion contributors,
`_LEG3_CATEGORIES`) and the `TrifectaFinding` type. Static-only, additive, advisory.

---

## Architecture

### System Overview
```
TrifectaAnalyzer.analyze_server / analyze_fleet
        │ (only when a finding fires)
        ▼
_compute_rule_of_two(leg1, leg2, leg3)  → recommended drop + action + affected tools + alternatives
        │
        ▼
TrifectaFinding.rule_of_two ──▶ report.py / htmlreport.py / sarif.py
```
The posture is computed only when the trifecta already fires — it never changes *when* a finding
is raised, only enriches it. No new inference, no network calls (matches the `trifecta.py`
module invariant).

### Integration points (existing code)
`trifecta.py` already computes the three leg contributor lists inside both passes:
`analyze_server` builds `leg1 = _tools_for_category(audit, _LEG1_CATEGORIES)`,
`leg2 = _ingestion_contributors(audit)`, `leg3 = _tools_for_category(audit, _LEG3_CATEGORIES)`,
and fires a HIGH finding when all three are non-empty. `analyze_fleet` accumulates the same three
contributor lists across servers and fires a MEDIUM advisory when the union covers all legs and
no single server already fired. The new `_compute_rule_of_two(...)` is called at exactly those two
fire sites, fed the same contributor lists, and its result is attached to the `TrifectaFinding`
via the new `rule_of_two` field. No other call sites change; non-firing servers never compute a
posture.

### Recommended-drop heuristic (precise)
Given the three contributor lists (each a list of `(server_name, tool_name)` pairs), choose the
single leg to recommend dropping:

1. **Prefer Leg 3 (exfiltration)** when `leg3` has ≥1 contributor. Rationale: removing the
   exfiltration channel breaks the trifecta with the least loss of read/ingest utility, and Leg 3
   is enforceable today via the egress detector (`--egress-check` allowlist). Action text:
   "restrict outbound destinations via `--egress-check` allowlist, or remove tool(s) {leg3 tools}".
2. **Otherwise, drop the leg with the fewest contributing tools** (tie-break: lower leg number).
   Rationale: fewest tools removed = least functionality lost. Action text is the per-leg string
   from `taxonomy` with the affected tool names substituted.
3. **`affected_tools`** = the tool names from the chosen leg's contributor list (deduplicated,
   preserving order).
4. **`alternatives`** = the other two legs, each as `(leg_number, action_text)`, so the operator
   can choose a different trade-off.
5. **Fleet findings** (cross-server): when the chosen leg's contributors span multiple servers,
   prefer the leg whose contributors are most concentrated on a single server (so the remediation
   targets one server); if still split, keep the Leg-3-first rule and label the posture
   "advisory, fleet-spanning" in the description.

The heuristic is deterministic and pure — no inference, no I/O — so it is fully unit-testable
against fixtures.

### File Structure (real paths)
```
src/mcp_audit/trifecta.py     # EDIT — _compute_rule_of_two; attach in analyze_server + analyze_fleet
src/mcp_audit/models.py       # EDIT — RuleOfTwoPosture dataclass; rule_of_two field on TrifectaFinding
src/mcp_audit/taxonomy.py     # EDIT — per-leg action strings + posture description
src/mcp_audit/report.py       # EDIT — text rendering
src/mcp_audit/htmlreport.py   # EDIT — HTML rendering
src/mcp_audit/sarif.py        # EDIT — SARIF note + recommendation text
docs/TRIFECTA-DETECTION.md    # EDIT — Rule of Two section + Meta Oct 2025 reference
tests/test_trifecta.py        # EDIT — posture computation cases
CHANGELOG.md                  # EDIT — feature entry
```

### Data Model
Not applicable — mcp-audit is a stateless static analyzer; the posture is an in-memory dataclass
on the finding. No persistence changes.

### Type Definitions
```python
# models.py additions
@dataclass(frozen=True)
class RuleOfTwoPosture:
    legs_present: list[int]                 # subset of [1, 2, 3]
    recommended_drop: int                   # leg to remove (1 | 2 | 3)
    action: str                             # concrete remediation text
    affected_tools: list[str]               # tools tied to the dropped leg
    alternatives: list[tuple[int, str]]     # (leg, action) for the other two legs

# TrifectaFinding gains:  rule_of_two: RuleOfTwoPosture | None = None
```
```python
# trifecta.py — pure, deterministic, no I/O
def _compute_rule_of_two(
    leg1: list[tuple[str, str]],
    leg2: list[tuple[str, str]],
    leg3: list[tuple[str, str]],
) -> RuleOfTwoPosture: ...
```
Worked example — a server holding all three legs where Leg 3 has one tool (`upload_file`):
```python
RuleOfTwoPosture(
    legs_present=[1, 2, 3],
    recommended_drop=3,
    action="restrict outbound destinations via --egress-check allowlist, or remove tool 'upload_file'",
    affected_tools=["upload_file"],
    alternatives=[
        (1, "remove file-read access (tool 'read_file')"),
        (2, "remove/disable the ingestion tool 'fetch_url'"),
    ],
)
```
When Leg 3 is empty (e.g., exfiltration arises only from a fleet peer), the heuristic falls to the
fewest-tools branch and `recommended_drop` becomes whichever of Leg 1 / Leg 2 has fewer
contributing tools.

### API Contracts
Not applicable — no external APIs or network calls; the posture is derived from leg contributors
already present on the `TrifectaFinding`.

### Dependencies
No new dependencies:
```bash
uv sync
uv run pytest -q
```

## Scope Boundaries
**In scope:** `RuleOfTwoPosture` model, the leg-to-drop heuristic + action mapping in
`trifecta.py`, attaching posture to per-server and fleet findings, and rendering in
text/HTML/SARIF + docs.
**Out of scope:** changing when the trifecta fires; auto-remediation or config mutation; a new
policy gate (the existing `fail_on.trifecta` already covers enforcement — posture is advisory).
**Deferred:** none — this is the standalone fast-follow to the egress bundle.

## Security & Credentials
- No credentials in scope — posture is derived from existing leg contributors.
- Nothing leaves the machine; no network calls.
- Advisory only — never mutates config or suppresses findings; references tool names already in the finding, no credential values.

---

## Phase 0: Foundation — model + posture computation (Week 1, ~3h)
**Objective:** the `RuleOfTwoPosture` model, taxonomy action strings, and the computation that
attaches a posture to every trifecta finding when it fires. No rendering.
**Tasks:**
1. Add `RuleOfTwoPosture` to `models.py` and a `rule_of_two: RuleOfTwoPosture | None = None` field to `TrifectaFinding`. — Acceptance: `python -c "from mcp_audit.models import RuleOfTwoPosture"` succeeds; existing `TrifectaFinding(...)` construction still works (field defaults None).
2. Add per-leg action strings + posture description to `taxonomy.py` (Leg 1 → "remove file-read access to tool X"; Leg 2 → "remove/disable the ingestion tool X"; Leg 3 → "restrict outbound destinations via --egress-check allowlist, or remove tool X"). — Acceptance: a `taxonomy` lookup returns a non-empty action string per leg.
3. Implement `_compute_rule_of_two(leg1, leg2, leg3)` in `trifecta.py`: pick the recommended drop (prefer Leg 3 when it has ≥1 tool, else the leg with the fewest contributing tools), build action + affected_tools + alternatives; attach in both `analyze_server` and `analyze_fleet`. — Acceptance: `tests/test_trifecta.py` asserts a fired finding's `rule_of_two` lists all 3 legs, exactly 1 `recommended_drop`, ≥1 `affected_tools`, 2 `alternatives`.
4. Author/extend fixtures: one server with all three legs where Leg 3 has a tool, one where Leg 3 is empty (forces the fewest-tools branch). — Acceptance: both fixtures drive `test_trifecta.py` and exercise both heuristic branches.
**Verification checklist:**
- [ ] `uv run pytest tests/test_trifecta.py -q` → green
- [ ] A 2-leg server yields no finding and no posture computed
- [ ] `uv run pytest tests/test_trifecta_integration.py -q` → still green
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: Task 1 (model), Task 2 (taxonomy), Task 4 (fixtures) — independent files; Task 3 consumes all three.
- Subagent type: coder
- Rationale: model, taxonomy, and fixtures have no inter-dependency; only the computation depends on them.
**Risks:**
- Heuristic recommends a leg the user needs: Mitigation → default Leg 3 + list all alternatives → Fallback: emit the ranked list only, no single pick.
- Fleet posture spans servers: Mitigation → recommend the leg whose contributors concentrate on one server → Fallback: label fleet posture "advisory, fleet-spanning."
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.

---

## Phase 1: Rendering + docs (Week 1–2, ~3h)
**Objective:** surface the posture everywhere trifecta findings render, and document it.
**Tasks:**
1. Render the posture in `report.py` (text): under each trifecta finding, a compact line — "Rule of Two: legs {…}; recommended — drop Leg N: {action}; alternatives: …". — Acceptance: the text report on the fixture shows the posture block; `test_report.py` extended.
2. Render in `htmlreport.py` and `sarif.py` (SARIF: result message + a related-location note carrying the action). — Acceptance: HTML shows the posture; the SARIF result carries the recommendation; `test_htmlreport.py` / `test_sarif.py` extended and green.
3. Update `docs/TRIFECTA-DETECTION.md` with a Rule of Two section citing Meta's Oct 2025 framework + the leg-drop heuristic, and add a `CHANGELOG.md` entry. — Acceptance: doc section exists and is linked; CHANGELOG has a dated entry.
**Verification checklist:**
- [ ] `mcp-audit audit --trifecta-check` on the fixture prints the posture in the text report
- [ ] `uv run pytest -q` → entire suite green (zero regressions)
- [ ] SARIF output validates against the repo's existing SARIF fixture
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: the three render targets — `report.py`, `htmlreport.py`, `sarif.py` — plus the docs (Task 3) are independent once the posture model is stable.
- Subagent type: coder
- Rationale: separate files, no shared state beyond the finished `RuleOfTwoPosture`.
**Risks:**
- SARIF has no native remediation slot: Mitigation → use the result message + a related-location note → Fallback: append the action to the finding description.
- Posture clutters the report when many servers fire: Mitigation → one compact line per finding → Fallback: gate verbose posture behind `--verbose`.
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.

---

## Feature-level Definition of Done
- Every fired trifecta finding (per-server and fleet) carries a non-null `rule_of_two` posture.
- The posture names all legs present, exactly one `recommended_drop`, ≥1 `affected_tool`, and two `alternatives`.
- The recommended drop defaults to Leg 3 whenever Leg 3 has ≥1 contributing tool; otherwise the fewest-tools leg.
- The posture renders in the text report, the HTML report, and SARIF output.
- `--trifecta-check` off → no posture computed and no behavior change anywhere.
- `uv run pytest -q` is fully green, including the extended `test_trifecta.py`, the renderer tests, and `test_trifecta_integration.py`; `docs/TRIFECTA-DETECTION.md` and `CHANGELOG.md` are updated.
