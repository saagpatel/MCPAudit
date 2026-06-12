# mcp-audit Egress Bundle (D3 + D1) — Implementation Roadmap

Feature addition to the existing `MCPAudit` repo at `/Users/d/Projects/MCPAudit`
(`src/mcp_audit/`). **Not greenfield** — read the existing modules first and follow their
patterns: opt-in detector flags (`--trifecta-check`), additive finding types
(`SsrfFinding`, `TrifectaFinding`), static-only analysis, never read credential values.

---

## Architecture

### System Overview
```
discovery/ ──▶ connector / analyzer ──▶ existing detectors (ssrf, trifecta, injection, ...)
                                              │
                                              ▼
                          NEW egress.EgressDetector
                          (consumes ssrf findings + resource URIs + allowlist)
                                              │
                                              ▼
                  ServerAudit.egress_findings ──▶ report.py / htmlreport.py / sarif.py
                                              │
                                              ▼
              policy.evaluate_policy(fail_on.egress, egress_allowlist)
```
The detector is additive: existing detectors and default output are untouched. Egress runs
only under `--egress-check`. It reuses `ssrf.py` host primitives as the single source of
destination truth, so SSRF and egress never disagree about what host a target resolves to.

### File Structure (real paths)
```
src/mcp_audit/egress.py               # NEW — EgressDetector, MULTI_TENANT_API_HOSTS, residual
src/mcp_audit/models.py               # EDIT — EgressFinding, EgressKind, EgressSeverity; ServerAudit.egress_findings
src/mcp_audit/taxonomy.py             # EDIT — egress_metadata(), MCP0xx-EGRESS rule ids
src/mcp_audit/policy.py               # EDIT — fail_on.egress, egress_allowlist, per-server egress rules
src/mcp_audit/cli.py                  # EDIT — --egress-check, --egress-allowlist, --multi-tenant-hosts
src/mcp_audit/analyzer.py             # EDIT — invoke EgressDetector, attach to ServerAudit
src/mcp_audit/report.py               # EDIT — text rendering
src/mcp_audit/htmlreport.py           # EDIT — HTML rendering
src/mcp_audit/sarif.py                # EDIT — SARIF result emission
docs/EGRESS-DETECTION.md              # NEW — detector doc (mirror SSRF-DETECTION.md)
examples/policies/egress.yaml         # NEW — sample policy
tests/test_egress.py                  # NEW — unit
tests/test_egress_integration.py      # NEW — end-to-end
tests/fixtures/                       # EDIT — egress fixtures (Cowork pattern + fixed-host URIs)
CHANGELOG.md                          # EDIT — feature entry
```

### Data Model
Not applicable — mcp-audit is a stateless static analyzer. Findings are in-memory dataclasses;
the only persistence (the pin baseline YAML owned by `pinning.py`) is unchanged. Shared shapes
are the dataclasses below.

### Type Definitions
```python
# models.py additions
class EgressKind(str, Enum):
    DESTINATION_OUTSIDE_ALLOWLIST = "destination_outside_allowlist"
    UNBOUNDED_EGRESS = "unbounded_egress"            # caller-controlled target; not allowlistable
    TRUSTED_DESTINATION_RESIDUAL = "trusted_destination_residual"  # D1 — Cowork class

class EgressSeverity(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"

@dataclass(frozen=True)
class EgressFinding:
    target_type: CapabilityTarget        # reuse existing TOOL | RESOURCE
    target_name: str
    severity: EgressSeverity
    kind: EgressKind
    destination_host: str | None         # None when caller-controlled / unbounded
    evidence: list[str]
    description: str
    rule_id: str                         # "MCP040-EGRESS"

# ServerAudit gains: egress_findings: list[EgressFinding] = field(default_factory=list)
```
```python
# egress.py
class EgressDetector:
    def __init__(self, allowlist: set[str], multi_tenant_hosts: set[str] | None = None) -> None: ...
    def scan_server(self, audit: ServerAudit) -> list[EgressFinding]: ...
```

### API Contracts
Not applicable — the detector makes no external API or network calls. It reads already-parsed
tool schemas, resource URIs, and SSRF findings in-process, consistent with `ssrf.py`'s
guarantee that no network request is ever made.

### Dependencies
No new dependencies. Existing environment only:
```bash
uv sync
uv run pytest -q
```

## Scope Boundaries
**In scope:** the `egress.py` detector (destination-outside-allowlist + unbounded-egress + D1
trusted-destination residual), `EgressFinding` model, taxonomy, `fail_on.egress` policy gate +
`egress_allowlist` config, CLI flags, report/HTML/SARIF rendering, docs, tests.
**Out of scope:** mutating `ssrf.py` suppression semantics; ETDI provider-signature verification
(parked — local hash-pin already covers the operative behavior); a dedicated env/log
credential-value scanner (redaction.py + provenance.py already cover most of it).
**Deferred:** Rule of Two posture remediation in `trifecta.py` (D2) — separate fast-follow.

## Security & Credentials
- Credential storage: none in scope — reads schemas/URIs/findings only.
- Data boundaries: nothing leaves the machine; zero network calls (asserted by test).
- Preserve invariants: never read/log/store credential values — credential signals are
  param-name and userinfo-template only.
- Additive + backward compatible: behind `--egress-check`; new policy keys optional, default off.

---

## Phase 0: Foundation — model + taxonomy + detector core (Week 1, ~4h)
**Objective:** `EgressFinding` model, taxonomy entries, and an `EgressDetector` that classifies
fixed destinations against an allowlist and flags caller-controlled egress. No CLI/report/policy
wiring.
**Tasks:**
1. Add `EgressKind`, `EgressSeverity`, `EgressFinding` to `models.py`; add `egress_findings` to `ServerAudit`. — Acceptance: `python -c "from mcp_audit.models import EgressFinding, EgressKind"` succeeds; `ServerAudit().egress_findings == []`.
2. Add `egress_metadata()` + `MCP0xx-EGRESS` rule ids to `taxonomy.py` for the three kinds. — Acceptance: `taxonomy.egress_metadata(EgressKind.UNBOUNDED_EGRESS).description` is non-empty with a stable rule id.
3. Implement `EgressDetector.scan_server`: enumerate fixed destination hosts (reuse `ssrf._finding_fixed_host` over SSRF findings + resource URIs), match via `ssrf.host_in_allowlist`, emit `DESTINATION_OUTSIDE_ALLOWLIST` for fixed hosts not allowlisted and `UNBOUNDED_EGRESS` for caller-controlled targets. — Acceptance: `tests/test_egress.py` covers fixed-host-outside → MEDIUM, fixed-host-inside → none, caller-controlled tool → HIGH unbounded.
4. Author `tests/fixtures/` egress inputs (fixed-host URIs, caller-controlled tool, allowlisted host). — Acceptance: fixtures load and drive `test_egress.py`.
**Verification checklist:**
- [ ] `uv run pytest tests/test_egress.py -q` → all green
- [ ] A test patches the socket/HTTP layer and asserts zero network calls during `scan_server`
- [ ] `python -c "from mcp_audit.egress import EgressDetector"` imports clean
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: Task 1 (model), Task 2 (taxonomy), Task 4 (fixtures) — no inter-dependency; Task 3 consumes all three.
- Subagent type: coder
- Rationale: model, taxonomy, and fixtures are independent files; only the detector depends on them.
**Risks:**
- Reusing SSRF internals couples modules: Mitigation → import only public helpers (`parse_host_allowlist`, `host_in_allowlist`, `_finding_fixed_host`) → Fallback: lift host helpers into a shared `netutil.py`.
- Empty fixed-destination set on realistic servers: Mitigation → `UNBOUNDED_EGRESS` is the primary signal → Fallback: document the expectation in the detector doc.
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.

---

## Phase 1: D1 trusted-destination residual (Week 1–2, ~4h)
**Objective:** stop treating an allowlisted host as automatically safe when it is a multi-tenant
data-bearing API or the tool can attach caller-controlled credentials (the Cowork lesson).
**Tasks:**
1. Add a curated `MULTI_TENANT_API_HOSTS` constant to `egress.py` (anthropic/openai APIs, S3/GCS/Azure blob, webhook/paste hosts), lowercased, subdomain-matched. — Acceptance: module constant present; matching reuses the `host_in_allowlist` subdomain rule.
2. Add caller-controlled-credential detection: credential-bearing if a param-name token ∈ `{auth, token, key, apikey, api_key, secret, bearer, credential}` or a resource URI templates userinfo. — Acceptance: unit test — `api_key` param → True; `query` param → False (exact-token match, not substring).
3. Emit `TRUSTED_DESTINATION_RESIDUAL` (LOW/MEDIUM, never HIGH) when an allowlisted fixed host ∈ `MULTI_TENANT_API_HOSTS` **or** the tool is credential-bearing. — Acceptance: Cowork fixture (allowlisted `api.anthropic.com` + `api_key`) → one residual; allowlisted plain host, no credential param → none.
4. Document the downgrade-not-suppress boundary vs `ssrf.filter_allowlisted_ssrf` in the `egress.py` docstring. — Acceptance: boundary stated; `ssrf.py` behavior unchanged (its tests stay green).
**Verification checklist:**
- [ ] `uv run pytest tests/test_egress.py -q` (residual cases) → green
- [ ] `uv run pytest tests/test_ssrf.py -q` → still green (no SSRF regression)
**Risks:**
- Multi-tenant host list false positives: Mitigation → conservative curated default + config extension + LOW/MEDIUM cap → Fallback: `--trusted-destination-check` opt-in sub-flag.
- Credential token set over-matches benign params: Mitigation → exact token match → Fallback: tune against the validation corpus.
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.

---

## Phase 2: Policy gate + config (Week 2, ~3h)
**Objective:** CI enforcement — `fail_on.egress` threshold + `egress_allowlist` (global and
per-server) without breaking existing policy files.
**Tasks:**
1. Extend `PolicyConfig` + `ServerPolicyConfig` with `fail_on_egress_severity`, `egress_allowlist`, `multi_tenant_hosts`; parse from `fail_on.egress` and top-level `egress_allowlist`. — Acceptance: `load_policy` parses a file with the new keys; a file without them still parses (existing fixtures green).
2. Wire egress into `evaluate_policy`: emit `PolicyViolation(rule="fail_on.egress", ...)` per finding at/above threshold (mirror the SSRF gate block, reuse `_effective_threshold` + `_SEVERITY_RANK`). — Acceptance: `fail_on.egress: medium` on a one-MEDIUM fixture → `PolicyResult(passed=False)`; absent → `passed=True`.
3. Add `examples/policies/egress.yaml`. — Acceptance: `load_policy(examples/policies/egress.yaml)` parses; covered by `test_examples.py`.
**Verification checklist:**
- [ ] `uv run pytest tests/test_policy.py tests/test_examples.py -q` → green
- [ ] An old key-less policy fixture still parses to the same result (backward-compat regression test)
**Risks:**
- Backward-compat break in parsing: Mitigation → optional keys, default off → Fallback: regression fixture pinning an old policy's parse.
- Threshold semantics drift: Mitigation → reuse `_effective_threshold`/`_SEVERITY_RANK` → Fallback: mirror the SSRF gate exactly.
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.

---

## Phase 3: CLI + report/SARIF/HTML + docs (Week 2–3, ~4h)
**Objective:** make the detector usable and visible end to end.
**Tasks:**
1. Add `--egress-check`, `--egress-allowlist`, `--multi-tenant-hosts` to `cli.py`; invoke the detector in the audit path and attach findings to `ServerAudit`. — Acceptance: `mcp-audit audit --egress-check --egress-allowlist api.anthropic.com` runs and prints egress findings.
2. Render egress findings in `report.py` (text), `htmlreport.py` (HTML), `sarif.py` (SARIF result with the egress rule id). — Acceptance: each renderer shows ≥1 egress finding on the fixture; `test_report.py` / `test_htmlreport.py` / `test_sarif.py` extended and green.
3. Write `docs/EGRESS-DETECTION.md` (mirror SSRF/TRIFECTA docs: what it detects, the D1 residual rationale citing the trusted-destination class, config, limits) + link from the README detector list + `CHANGELOG.md` entry. — Acceptance: doc exists and is linked; CHANGELOG has a dated entry.
4. Add `tests/test_egress_integration.py` (discovery → analyzer → egress findings → policy gate). — Acceptance: integration test green; full `uv run pytest -q` green.
**Verification checklist:**
- [ ] `mcp-audit audit --egress-check --egress-allowlist api.anthropic.com` on the fixture fleet prints egress findings
- [ ] `uv run pytest -q` → entire suite green (40+ files, zero regressions)
- [ ] SARIF output validates against the repo's existing SARIF fixture
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: the three renderers in Task 2 (`report.py`, `htmlreport.py`, `sarif.py`) and Task 3 (docs) — separate files, no shared state once `EgressFinding` is stable.
- Subagent type: coder
- Rationale: each renderer and the docs touch independent files; they only consume the finished finding model.
**Risks:**
- Report layout churn across three renderers: Mitigation → follow the existing per-detector section pattern → Fallback: ship text first, HTML/SARIF as a follow-up commit.
- SARIF schema validity: Mitigation → reuse the existing SARIF result builder → Fallback: validate against the repo's SARIF fixture.
**Phase-end review:** Run `/ultrareview`. Address all findings before marking the phase complete.
