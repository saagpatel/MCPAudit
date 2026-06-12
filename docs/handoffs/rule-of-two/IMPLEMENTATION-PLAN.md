# mcp-audit Rule of Two Posture (D2) — Implementation Plan

Feature addition to the existing `MCPAudit` repo (`src/mcp_audit/trifecta.py`). **Not
greenfield** — it enriches the existing trifecta detector. Reuses its leg model and finding
type; static-only, additive, advisory.

---

## Section 1: EXEC SUMMARY

### 1a. What we're building
An enrichment to mcp-audit's trifecta detector: when `trifecta.py` fires (per-server HIGH or
fleet-level MEDIUM), the finding additionally carries a **Rule of Two posture** — it names the
three legs present and recommends the single lowest-cost leg to remove with a concrete action
(e.g., "drop the exfiltration leg: restrict outbound destinations / remove tool `upload_file`").
This maps Meta's October 2025 Agents Rule of Two onto each finding, turning a risk flag into an
actionable remediation. Static-only, additive, rendered in text/HTML/SARIF.

### 1b. Riskiest parts and de-risking strategy
- **R1 — bad leg-to-drop advice (MEDIUM).** Why: "lowest cost" is contextual; recommending the user drop the leg they most need erodes trust. Mitigation: the heuristic defaults to Leg 3 (exfiltration) via egress restriction as the cheapest (least functionality lost, and now enforceable by the egress detector), then the leg with the fewest contributing tools; the posture lists **all three** legs plus alternatives, never a single prescriptive order. Fallback: present the recommendation as a ranked list of all three drop-options rather than one pick.
- **R2 — scope creep into auto-remediation (LOW).** Why: tempting to "fix" rather than advise. Mitigation: posture is advisory text + structured data only; it never mutates config or suppresses findings. Fallback: none needed.
- **R3 — coupling to the egress bundle (MEDIUM).** Why: "drop Leg 3 via egress allowlist" references the egress feature, which may not be merged yet. Mitigation: phrase the action generically ("restrict outbound destinations"), and reference `--egress-check` as the enforcement path only when present; the posture works standalone. Fallback: posture degrades to "remove the exfil-capable tool" if the egress detector is absent.

### 1c. Shortest path to daily personal use
Ship Phase 0 by end of week 1 — posture computed and attached to findings, visible in the text
report; that is ~80% of the value. Phase 1 by end of week 1.5 adds HTML + SARIF rendering and
the doc update for the remaining ~20%.

---

## Section 2: REVIEW GATE (SPEC LOCK)

### 2a. Goal
Every trifecta finding carries an actionable Rule-of-Two remediation naming which leg to drop
and how.

### 2b. Success metrics
- On the per-server trifecta fixture, the finding gains a posture naming all 3 legs, exactly 1 recommended drop, and ≥1 affected tool.
- The recommendation defaults to dropping Leg 3 (exfiltration) in 100% of fixtures where Leg 3 has ≥1 contributing tool.
- Posture renders in text, HTML, and SARIF; `test_trifecta.py` + the three renderer tests are extended; the full suite (40+ files) stays green.
- Zero behavior change when `--trifecta-check` is off — the posture is computed only when a finding fires.

### 2c. Hard constraints
- Static analysis only — no network calls, no new inference (matches the `trifecta.py` header invariant).
- Additive — does not change *when* the trifecta fires, only enriches the finding.
- Advisory only — no auto-remediation, no config mutation, no finding suppression.
- No new runtime dependencies.

### 2d. Locked decisions
- **Decision:** where the posture lives. **Locked to:** a `RuleOfTwoPosture | None` field on `TrifectaFinding`, computed in `TrifectaAnalyzer`. **Rationale:** matches the finding-centric model; renderers read it straight off the finding, like every other finding attribute.
- **Decision:** leg-to-drop heuristic. **Locked to:** prefer Leg 3 (exfiltration → restrict egress) > the leg with the fewest contributing tools. **Rationale:** lowest functionality loss, and Leg 3 is now enforceable via the egress detector.
- **Decision:** recommendation shape. **Locked to:** one primary recommendation + the other two legs as listed alternatives. **Rationale:** actionable without being prescriptive-only (de-risks R1).

---

## Section 3: ARCHITECTURE

### 3a. System diagram
```
TrifectaAnalyzer.analyze_server / analyze_fleet
        │ (on fire)
        ▼
compute RuleOfTwoPosture (legs present → recommended drop + action + affected tools)
        │
        ▼
TrifectaFinding.rule_of_two ──▶ report.py / htmlreport.py / sarif.py
```

### 3b. Tech stack
- Python 3.12+ (repo `.python-version`) — static, no runtime.
- stdlib only (no parsing/network).
- `pytest` via `uv run pytest` — existing runner.
- No new dependencies.

### 3c. File structure
```
src/mcp_audit/trifecta.py     # EDIT — compute posture when a finding fires
src/mcp_audit/models.py       # EDIT — RuleOfTwoPosture dataclass; rule_of_two field on TrifectaFinding
src/mcp_audit/taxonomy.py     # EDIT — per-leg action strings + posture description
src/mcp_audit/report.py       # EDIT — text rendering
src/mcp_audit/htmlreport.py   # EDIT — HTML rendering
src/mcp_audit/sarif.py        # EDIT — SARIF note/related-location
docs/TRIFECTA-DETECTION.md    # EDIT — document the Rule of Two posture + Meta reference
tests/test_trifecta.py        # EDIT — posture computation cases
CHANGELOG.md                  # EDIT — feature entry
```

### 3d. Data model
Not applicable for this project: mcp-audit is a stateless static analyzer; the posture is an
in-memory dataclass on the finding. No persistence changes.

### 3e. Type definitions
```python
# models.py additions
@dataclass(frozen=True)
class RuleOfTwoPosture:
    legs_present: list[int]                 # subset of [1, 2, 3]
    recommended_drop: int                   # the leg to remove (1 | 2 | 3)
    action: str                             # concrete remediation text
    affected_tools: list[str]               # tools tied to the dropped leg
    alternatives: list[tuple[int, str]]     # (leg, action) for the other two legs

# TrifectaFinding gains:
#   rule_of_two: RuleOfTwoPosture | None = None
```

### 3f. API contracts
Not applicable for this project: no external APIs and no network calls — the posture is derived
from the leg contributors already on the `TrifectaFinding`.

### 3g. Dependencies
No new dependencies. Existing environment only:
```bash
uv sync
uv run pytest -q
```

---

## Section 4: PHASED IMPLEMENTATION

### Phase 0: Foundation — model + posture computation (Week 1, ~3h)
**Objective:** the `RuleOfTwoPosture` model, taxonomy action strings, and the computation that
attaches a posture to every trifecta finding when it fires. No rendering.
**Tasks:**
1. Add `RuleOfTwoPosture` to `models.py` and a `rule_of_two: RuleOfTwoPosture | None = None` field to `TrifectaFinding`. — Acceptance: `python -c "from mcp_audit.models import RuleOfTwoPosture"` succeeds; existing `TrifectaFinding(...)` calls still construct (field defaults to None).
2. Add per-leg action strings + a posture description to `taxonomy.py` (Leg 1 → "remove file-read access to tool X"; Leg 2 → "remove/disable the ingestion tool X"; Leg 3 → "restrict outbound destinations (e.g. --egress-check allowlist) or remove tool X"). — Acceptance: `taxonomy` exposes a lookup returning a non-empty action string per leg.
3. Implement `_compute_rule_of_two(leg1, leg2, leg3)` in `trifecta.py`: choose the recommended drop (prefer Leg 3 when it has ≥1 tool, else the leg with the fewest contributing tools), build action + affected_tools + alternatives; attach to the finding in both `analyze_server` and `analyze_fleet`. — Acceptance: `tests/test_trifecta.py` asserts a fired finding has `rule_of_two` with all 3 legs, exactly 1 `recommended_drop`, ≥1 `affected_tools`, and 2 `alternatives`.
4. Author/extend fixtures: a server with all three legs where Leg 3 has a tool, and one where Leg 3 is empty (forces the fewest-tools branch). — Acceptance: both fixtures drive `test_trifecta.py` and exercise both heuristic branches.
**Verification checklist:**
- [ ] `uv run pytest tests/test_trifecta.py -q` → green
- [ ] A non-firing server (only 2 legs) yields a finding-free result with no posture computed
- [ ] `uv run pytest tests/test_trifecta_integration.py -q` → still green (no regression)
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: Task 1 (model), Task 2 (taxonomy), Task 4 (fixtures) — independent files; Task 3 consumes all three.
- Subagent type: coder
- Rationale: model, taxonomy, and fixtures have no inter-dependency; only the computation depends on them.
**Risks:**
- Heuristic recommends a leg the user needs: Mitigation → default Leg 3 + list all alternatives → Fallback: emit the ranked list only, no single pick.
- Fleet-level posture spans servers (the dropped leg lives on a different server): Mitigation → for fleet findings, recommend the leg whose contributors are most concentrated on one server → Fallback: label fleet posture "advisory, fleet-spanning."

### Phase 1: Rendering + docs (Week 1–2, ~3h)
**Objective:** surface the posture everywhere trifecta findings render, and document it.
**Tasks:**
1. Render the posture in `report.py` (text): under each trifecta finding, print "Rule of Two: legs present {…}; recommended — drop Leg N: {action}; alternatives: …". — Acceptance: the text report on the fixture shows the posture block; `test_report.py` extended.
2. Render in `htmlreport.py` and `sarif.py` (SARIF: attach as a note + the action as a fix suggestion). — Acceptance: HTML shows the posture; SARIF result carries the recommendation text; `test_htmlreport.py` / `test_sarif.py` extended and green.
3. Update `docs/TRIFECTA-DETECTION.md` with a Rule of Two section citing Meta's Oct 2025 framework + the leg-drop heuristic + a `CHANGELOG.md` entry. — Acceptance: doc section exists; CHANGELOG has a dated entry.
**Verification checklist:**
- [ ] `mcp-audit audit --trifecta-check` on the fixture prints the posture in the text report
- [ ] `uv run pytest -q` → entire suite green (zero regressions)
- [ ] SARIF output validates against the repo's existing SARIF fixture
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: the three render targets — `report.py`, `htmlreport.py`, `sarif.py` — and the docs (Task 3) are independent once the posture model is stable.
- Subagent type: coder
- Rationale: separate files, no shared state beyond the finished `RuleOfTwoPosture`.
**Risks:**
- SARIF has no native "remediation" slot: Mitigation → use the result message + a related-location note → Fallback: append the action to the finding description.
- Posture clutters the text report when many servers fire: Mitigation → one compact line per finding → Fallback: gate verbose posture behind `--verbose`.

---

## Section 5: SECURITY & CREDENTIALS
- **Credential storage:** No credentials in scope — the posture is derived from existing leg contributors.
- **Data boundaries:** Nothing leaves the machine; no network calls (matches the `trifecta.py` invariant).
- **Encryption at rest:** Not applicable — no new persistence.
- **Token rotation:** Not applicable — no tokens handled.
- **Sensitive data handling:** The posture references tool names already present in the finding; no credential values are read or emitted.

---

## Section 6: TESTING STRATEGY

**Phase 0** — Manual: run the detector on the all-three-legs fixture and read the computed posture. Automate: `test_trifecta.py` cases for the recommended-drop heuristic (Leg 3 present → drop Leg 3; Leg 3 empty → fewest-tools leg), posture completeness, and the non-firing (2-leg) no-posture case. Verify: two fixtures exercising both heuristic branches; expected `recommended_drop` and `alternatives` asserted.

**Phase 1** — Manual: render text/HTML/SARIF on the fixture and inspect the posture block. Automate: renderer tests asserting the posture appears in each output, plus `test_trifecta_integration.py` end-to-end. Verify: SARIF validates against the repo fixture; `uv run pytest -q` fully green.
