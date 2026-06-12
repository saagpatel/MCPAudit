# mcp-audit Egress Bundle (D3 + D1) — Implementation Plan

Feature addition to the existing `MCPAudit` repo (`src/mcp_audit/`, PyPI `mcp-permission-audit`).
This is **not greenfield** — it extends a mature static analyzer. All work reuses existing
patterns (opt-in detector flags, additive finding types, static-only analysis, never read
credential values).

---

## Section 1: EXEC SUMMARY

### 1a. What we're building
A destination-aware egress audit for mcp-audit: a new opt-in detector `egress.py` that, per
discovered MCP server, enumerates reachable **fixed** network destinations from tool schemas
and resource URIs, flags destinations outside a declared egress allowlist, and flags
caller-controlled egress as "unbounded — not allowlistable" (D3). It also adds a
**trusted-destination residual** (D1): an allowlisted host is no longer treated as automatically
safe when it is a known multi-tenant/data-bearing API or the tool can attach caller-controlled
credentials — the lesson from the January 2026 Claude Cowork exfil. The bundle adds a
`fail_on.egress` CI policy gate, an `egress_allowlist` config key, `--egress-check` /
`--egress-allowlist` CLI flags, and report/SARIF/HTML rendering. It performs zero network
calls and never reads credential values, consistent with the existing `ssrf.py` invariant.

### 1b. Riskiest parts and de-risking strategy
- **R1 — Multi-tenant-host false positives (MEDIUM).** Why: curating "data-bearing multi-tenant API" hosts is judgment-heavy; over-flagging erodes trust. Mitigation: ship a small, conservative, documented default constant (`api.anthropic.com`, `api.openai.com`, `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com`, `webhook.site`, common paste/file-share hosts), config-extensible, residuals emitted at LOW/MEDIUM only — never HIGH. Fallback: gate the residual behind a `--trusted-destination-check` sub-flag, opt-in until tuned.
- **R2 — Overlap with the SSRF detector (MEDIUM).** Why: SSRF and egress both reason about destinations; duplicate or contradictory findings confuse the report. Mitigation: `egress.py` consumes `ssrf.py`'s fixed-host extraction and findings as its single source of destination truth, with a documented boundary (SSRF = caller can *steer* destination; egress = destination *policy compliance*). Fallback: suppress egress "unbounded" findings on targets already HIGH-flagged by SSRF and cross-reference the rule ID.
- **R3 — Static "fixed destination" is often empty (MEDIUM).** Why: many tools take a URL param (caller-controlled), so the fixed-destination set is empty and the feature looks weak. Mitigation: treat caller-controlled egress as a first-class HIGH "unbounded egress — not allowlistable" finding (the honest, valuable signal), not a gap. Fallback: document that destination-allowlisting bites hardest on fixed-host resource URIs and pinned endpoints.
- **R4 — Policy schema backward compatibility (LOW).** Why: adding keys to `policy.py` must not break existing policy YAML files. Mitigation: `fail_on.egress` and `egress_allowlist` are optional and default-off (mirrors the existing optional `fail_on` keys); add policy fixtures asserting old files still parse. Fallback: document the schema addition in `docs/EGRESS-DETECTION.md`.

### 1c. Shortest path to daily personal use
Ship Phase 0 + Phase 1 by end of week 2 — the detector and the D1 residual run via
`--egress-check` and surface in the default report. That solves ~70% of the value (the new
signal exists and is visible). Phase 2 (CI policy gate) ships by end of week 2.5 and adds the
remaining ~25% (enforcement). Phase 3 (SARIF/HTML/docs) by end of week 3 closes the last ~5%.

---

## Section 2: REVIEW GATE (SPEC LOCK)

### 2a. Goal
mcp-audit can audit and CI-gate *where* each MCP server is allowed to send data — not only
whether it can exfiltrate — and stops treating an allowlisted multi-tenant API host as
automatically safe.

### 2b. Success metrics
- `--egress-check` issues **zero** network calls — asserted by a test that patches the socket/HTTP layer and verifies it is never invoked.
- On an 8-server fixture fleet, the detector flags 100% of resource URIs with fixed hosts outside a 3-host allowlist, and 100% of caller-controlled-fetch tools as "unbounded egress."
- The D1 residual fires on the Cowork-pattern fixture (allowlisted `api.anthropic.com` + a file-upload tool carrying a caller-supplied `api_key` param) and does **not** fire on an allowlisted host with no credential param and a non-data-bearing endpoint.
- `fail_on.egress: medium` flips the exit code to non-zero on a fixture with one MEDIUM egress finding; with `fail_on.egress` absent, the same run exits 0 (backward compatibility).
- `tests/test_egress.py` + `tests/test_egress_integration.py` are added and the full suite (40+ files) stays green with zero regressions.

### 2c. Hard constraints
- Static analysis only — no network requests, ever (matches the `ssrf.py` invariant).
- Never read or store credential values — credential signals are param-name / userinfo-template only (matches the `pinning.py` / `provenance.py` invariant).
- Additive and opt-in — behind `--egress-check`; default audit output unchanged; existing policy files keep parsing.
- No new runtime dependencies — reuse stdlib `urllib.parse` and existing `pyyaml`; reuse `ssrf.py` host primitives rather than re-implement them.

### 2d. Locked decisions
- **Decision:** where the residual logic lives. **Locked to:** `egress.py` consumes `ssrf.py` findings + the allowlist and re-derives the residual (downgrade-not-suppress); `ssrf.py`'s `filter_allowlisted_ssrf` is left intact for the SSRF report. **Rationale:** keeps SSRF semantics stable, avoids cross-detector coupling, one new module owns the new behavior.
- **Decision:** multi-tenant API host source. **Locked to:** a curated default constant in `egress.py`, extensible via a `multi_tenant_hosts` policy/CLI key. **Rationale:** no ecosystem registry of data-bearing multi-tenant APIs exists; a conservative curated list is the only defensible default.
- **Decision:** finding model. **Locked to:** a new frozen `EgressFinding` dataclass + `EgressKind` enum added to `models.py`, severity reusing the existing severity enum pattern. **Rationale:** matches the established per-detector finding pattern (`SsrfFinding`, `TrifectaFinding`, `DriftFinding`).
- **Decision:** CLI surface. **Locked to:** `--egress-check` (opt-in, mirrors `--trifecta-check`) + `--egress-allowlist h1,h2` (mirrors the existing SSRF allowlist flag); `--trusted-destination-check` folded under `--egress-check` by default. **Rationale:** consistency with existing opt-in detector flags.

---

## Section 3: ARCHITECTURE

### 3a. System diagram
```
discovery/ ──▶ connector/analyzer ──▶ existing detectors (ssrf, trifecta, injection, ...)
                                              │
                                              ▼
                        NEW egress.EgressDetector
                        (consumes ssrf findings + resource URIs + allowlist)
                                              │
                                              ▼
                    ServerAudit.egress_findings ──▶ report / sarif / htmlreport
                                              │
                                              ▼
                    policy.evaluate_policy(fail_on.egress, egress_allowlist)
```

### 3b. Tech stack
- Python 3.12+ (repo `.python-version`; matches existing modules) — static analysis, no runtime.
- `urllib.parse` stdlib (reuse `ssrf._finding_fixed_host` host extraction) — one-sentence: same parser the SSRF detector already trusts.
- `pyyaml` (already in `pyproject.toml`) — policy + examples parsing.
- `pytest` (existing) — `test_egress.py`, `test_egress_integration.py`.
- No new dependencies.

### 3c. File structure
```
src/mcp_audit/
├── egress.py              # NEW — EgressDetector, multi-tenant host set, residual logic
├── models.py              # EDIT — EgressFinding, EgressKind; add egress_findings to ServerAudit
├── taxonomy.py            # EDIT — egress_metadata(), rule IDs (MCP0xx-EGRESS)
├── policy.py              # EDIT — fail_on.egress, egress_allowlist, per-server egress rules
├── cli.py                 # EDIT — --egress-check, --egress-allowlist, --multi-tenant-hosts
├── analyzer.py            # EDIT — invoke EgressDetector, attach findings to ServerAudit
├── report.py              # EDIT — render egress findings (text)
├── htmlreport.py          # EDIT — render egress findings (HTML)
└── sarif.py               # EDIT — emit egress findings as SARIF results
docs/EGRESS-DETECTION.md   # NEW — detector doc (mirrors SSRF-DETECTION.md / TRIFECTA-DETECTION.md)
examples/policies/egress.yaml  # NEW — sample policy with fail_on.egress + egress_allowlist
tests/test_egress.py            # NEW — unit tests
tests/test_egress_integration.py# NEW — end-to-end via the analyzer + policy
tests/fixtures/                 # EDIT — egress fixtures (Cowork pattern, fixed-host URIs)
CHANGELOG.md                    # EDIT — feature entry
```

### 3d. Data model
Not applicable for this project: mcp-audit is a stateless static analyzer — findings are
in-memory dataclasses, and the only persistence (the pin baseline) is a YAML file owned by
`pinning.py` and is unchanged by this feature. Shared shapes are defined in Section 3e.

### 3e. Type definitions
```python
# models.py (additions)
from dataclasses import dataclass, field
from enum import Enum

class EgressKind(str, Enum):
    DESTINATION_OUTSIDE_ALLOWLIST = "destination_outside_allowlist"
    UNBOUNDED_EGRESS = "unbounded_egress"            # caller-controlled target; not allowlistable
    TRUSTED_DESTINATION_RESIDUAL = "trusted_destination_residual"  # D1 (Cowork class)

class EgressSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass(frozen=True)
class EgressFinding:
    target_type: "CapabilityTarget"     # TOOL | RESOURCE (reuse existing enum)
    target_name: str
    severity: EgressSeverity
    kind: EgressKind
    destination_host: str | None         # None for caller-controlled / unbounded
    evidence: list[str]
    description: str
    rule_id: str                         # e.g. "MCP040-EGRESS"

# ServerAudit gains: egress_findings: list[EgressFinding] = field(default_factory=list)
```
```python
# egress.py (detector signature)
class EgressDetector:
    def __init__(self, allowlist: set[str], multi_tenant_hosts: set[str] | None = None) -> None: ...
    def scan_server(self, audit: "ServerAudit") -> list[EgressFinding]: ...
```

### 3f. API contracts
Not applicable for this project: the detector makes no external API or network calls. It reads
already-parsed tool schemas, resource URIs, and SSRF findings in-process — consistent with the
`ssrf.py` guarantee that "no network request is ever made."

### 3g. Dependencies
No new dependencies. Existing environment only:
```bash
uv sync            # installs the pinned existing deps (pyyaml, etc.)
uv run pytest -q   # existing test runner
```

---

## Section 4: PHASED IMPLEMENTATION

### Phase 0: Foundation — model + taxonomy + detector core (Week 1, ~4h)
**Objective:** the `EgressFinding` model, taxonomy entries, and a working `EgressDetector` that
classifies fixed destinations against an allowlist and flags caller-controlled egress. No CLI,
report, or policy wiring yet.
**Tasks:**
1. Add `EgressKind`, `EgressSeverity`, `EgressFinding` to `models.py`; add `egress_findings` to `ServerAudit`. — Acceptance: `python -c "from mcp_audit.models import EgressFinding, EgressKind"` succeeds and `ServerAudit().egress_findings == []`.
2. Add `egress_metadata()` + rule IDs to `taxonomy.py` for the three kinds. — Acceptance: `taxonomy.egress_metadata(EgressKind.UNBOUNDED_EGRESS).description` returns a non-empty string and a stable `MCP0xx-EGRESS` rule id.
3. Implement `EgressDetector.scan_server`: enumerate fixed destination hosts (reuse `ssrf._finding_fixed_host` over the server's SSRF findings + resource URIs), match against the allowlist (`ssrf.host_in_allowlist`), emit `DESTINATION_OUTSIDE_ALLOWLIST` for fixed hosts not in the allowlist and `UNBOUNDED_EGRESS` for caller-controlled targets. — Acceptance: `tests/test_egress.py` covers (a) fixed host outside allowlist → MEDIUM finding, (b) fixed host inside allowlist → no finding, (c) caller-controlled URL param tool → HIGH unbounded finding.
4. Author `tests/fixtures/` egress inputs (fixed-host URIs, caller-controlled tool, allowlisted host). — Acceptance: fixtures load and are consumed by `test_egress.py`.
**Risks:**
- Reusing SSRF internals couples the modules: Mitigation → import only the public `parse_host_allowlist`/`host_in_allowlist`/`_finding_fixed_host` helpers → Fallback: lift the host helpers into a shared `netutil.py` if coupling grows.
- Empty fixed-destination set on realistic servers: Mitigation → `UNBOUNDED_EGRESS` is the primary signal, not a fallback → Fallback: document the expectation.
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: Task 1 (model), Task 2 (taxonomy), Task 4 (fixtures) — no code dependency among them; Task 3 consumes all three.
- Subagent type: coder
- Rationale: model, taxonomy, and fixtures are independent files; only the detector (Task 3) depends on them.

### Phase 1: D1 trusted-destination residual (Week 1–2, ~4h)
**Objective:** stop treating an allowlisted host as automatically safe when it is a multi-tenant
data-bearing API or the tool can attach caller-controlled credentials.
**Tasks:**
1. Add a curated `MULTI_TENANT_API_HOSTS` constant to `egress.py` (anthropic/openai APIs, S3/GCS/Azure blob, webhook/paste hosts). — Acceptance: the set is a module constant, lowercased, documented inline; `host_in_allowlist`-style subdomain matching reused.
2. Add caller-controlled-credential detection: a tool carries credential material if a param-name token is in `{auth, token, key, apikey, api_key, secret, bearer, credential}` or a resource URI templates userinfo. — Acceptance: a unit test confirms `api_key` param → credential-bearing True; `query` param → False.
3. Emit `TRUSTED_DESTINATION_RESIDUAL` (LOW/MEDIUM, never HIGH) when an allowlisted fixed host is in `MULTI_TENANT_API_HOSTS` **or** the tool is credential-bearing. — Acceptance: the Cowork-pattern fixture (allowlisted `api.anthropic.com` + `api_key` param) yields one residual finding; an allowlisted non-multi-tenant host with no credential param yields none.
4. Document the downgrade-not-suppress boundary vs `ssrf.filter_allowlisted_ssrf`. — Acceptance: `egress.py` module docstring states the boundary; no change to `ssrf.py` behavior (its tests stay green).
**Risks:**
- Multi-tenant host list false positives: Mitigation → conservative curated default + config extension + LOW/MEDIUM only → Fallback: `--trusted-destination-check` opt-in sub-flag.
- Credential-token set over-matches benign params: Mitigation → exact token match, not substring → Fallback: tune against the validation corpus.

### Phase 2: Policy gate + config (Week 2, ~3h)
**Objective:** CI enforcement — `fail_on.egress` severity threshold and `egress_allowlist` config,
global and per-server, without breaking existing policy files.
**Tasks:**
1. Extend `PolicyConfig` + `ServerPolicyConfig` with `fail_on_egress_severity` and `egress_allowlist` (+ `multi_tenant_hosts`); parse from `fail_on.egress` and top-level `egress_allowlist`. — Acceptance: `load_policy` parses a file with the new keys; a file without them still parses (existing fixtures green).
2. Wire egress into `evaluate_policy`: emit a `PolicyViolation(rule="fail_on.egress", ...)` for each egress finding at/above threshold (mirror the SSRF gate block). — Acceptance: `fail_on.egress: medium` on a one-MEDIUM-finding fixture returns `PolicyResult(passed=False)`; absent → `passed=True`.
3. Add `examples/policies/egress.yaml`. — Acceptance: `load_policy(examples/policies/egress.yaml)` parses without error and is covered by `test_examples.py`.
**Risks:**
- Backward-compat break in policy parsing: Mitigation → optional keys, default off → Fallback: a regression fixture pinning an old policy file's parse result.
- Threshold semantics drift from other detectors: Mitigation → reuse `_effective_threshold` + `_SEVERITY_RANK` → Fallback: mirror the SSRF gate exactly.

### Phase 3: CLI + report/SARIF/HTML + docs (Week 2–3, ~4h)
**Objective:** make the detector usable and visible end to end.
**Tasks:**
1. Add `--egress-check`, `--egress-allowlist`, `--multi-tenant-hosts` to `cli.py` and invoke the detector in the audit path (attach to `ServerAudit`). — Acceptance: `mcp-audit audit --egress-check --egress-allowlist api.anthropic.com` runs and prints egress findings.
2. Render egress findings in `report.py` (text), `htmlreport.py` (HTML), `sarif.py` (SARIF result with the egress rule id). — Acceptance: each renderer shows ≥1 egress finding on the fixture; `test_report.py` / `test_htmlreport.py` / `test_sarif.py` extended.
3. Write `docs/EGRESS-DETECTION.md` (mirror SSRF/TRIFECTA docs: what it detects, the D1 residual rationale citing the trusted-destination class, config, limits) + `CHANGELOG.md` entry. — Acceptance: doc exists, links from README detector list; CHANGELOG has a dated entry.
4. Add `tests/test_egress_integration.py` (discovery → analyzer → egress findings → policy gate). — Acceptance: integration test green; full suite green.
**Risks:**
- Report layout churn across three renderers: Mitigation → follow the existing per-detector section pattern → Fallback: ship text first, HTML/SARIF as a follow-up commit.
- SARIF schema validity: Mitigation → reuse the existing SARIF result builder → Fallback: validate against the repo's SARIF fixture.
**Parallel Dispatch Proposal (≥3 disjoint tasks):**
- Dispatchable in parallel: Task 2's three renderers (report / htmlreport / sarif) and Task 3 (docs) — independent files once the finding model is stable.
- Subagent type: coder
- Rationale: each renderer and the docs touch separate files with no shared state beyond the finished `EgressFinding`.

---

## Section 5: SECURITY & CREDENTIALS
- **Credential storage:** No credentials in scope — the detector reads schemas, URIs, and existing findings only.
- **Data boundaries:** Nothing leaves the machine; the detector makes zero network calls (a Section 2b metric asserts this).
- **Encryption at rest:** Not applicable — no new persistence; the pin YAML owned by `pinning.py` is unchanged.
- **Token rotation:** Not applicable — no tokens handled.
- **Sensitive data handling:** Credential *signals* are detected by parameter-name and userinfo-template only; values are never read, logged, or stored. The multi-tenant host list and rule metadata contain no secrets.

---

## Section 6: TESTING STRATEGY

**Phase 0** — Manual: run the detector on the fixtures and eyeball outside-allowlist vs unbounded classification. Automate: `test_egress.py` for the three classification cases + the no-network assertion. Verify: fixtures in `tests/fixtures/` with a known fixed-host URI, a caller-controlled tool, and an allowlisted host; expected finding kinds asserted.

**Phase 1** — Manual: confirm the Cowork-pattern fixture yields exactly one residual. Automate: unit tests for `MULTI_TENANT_API_HOSTS` matching, credential-param detection, and the LOW/MEDIUM-not-HIGH severity cap. Verify: a positive fixture (allowlisted `api.anthropic.com` + `api_key`) and a negative fixture (allowlisted plain host, no credential param) with expected counts.

**Phase 2** — Manual: run `mcp-audit` with and without `fail_on.egress` and check the exit code. Automate: `test_policy.py` additions — threshold pass/fail, backward-compat parse of a key-less policy. Verify: a one-MEDIUM-finding report fixture; assert `PolicyResult.passed` flips with the threshold present vs absent.

**Phase 3** — Manual: render text/HTML/SARIF on the fixture fleet and inspect the egress section. Automate: renderer tests + `test_egress_integration.py` (discovery → analyzer → findings → policy). Verify: SARIF output validates against the repo's existing SARIF fixture; full `uv run pytest -q` green.
