# Final revised Evidence Conservation Mutation Pilot specification

## 1. Exact changes from the prior specification

| Prior text or meaning | Revised text or meaning | Effect |
|---|---|---|
| Strict downgrade required ratification. | “Every primary mutation MUST have `authority < STRONG`, MUST be at or below its independently adjudicated ceiling, and MUST carry the correct evidence-disposition reason.” | Removes top-control vacuity permanently. |
| P1 binding responsibility was unresolved. | PCC owns the displayed decision’s binding of raw security receipt subject, project identity, and PortfolioTruth producer repository/revision. | P1-06 is normative and may expose a baseline defect. |
| P1 consumer input was effectively only the projected snapshot. | P1’s frozen seam input is the pair `{GitHubSecurityCoverageReceiptV1, one-project PortfolioTruth 0.11.0 snapshot}`. The current PCC path’s failure to consume both is observable behavior. | Makes the mismatch independently expressible without inventing oracle truth inside PCC. |
| P2’s “mcp-trust decision” could be read as global `publication_ready`. | P2 tests only `MCPTrustPerServerFixtureAdmissibilityV1`: fresh grade, receipt, scan, and snapshot binding inside deterministic fixture replay. `publication_ready`, publication, live scans, and scheduling are excluded. | Gives P2 a valid offline `STRONG` control. |
| The verdict lattice mixed claim strength with incomparable reason states. | Verdict strength is an authority order; missing/stale/masked/etc. are dispositions. The combined order is formalized below. | Makes strict comparison and case-specific ceilings non-vacuous while retaining explicit `UNKNOWN`/`UNSUPPORTED`. |
| All prerequisite records were described as prerequisites to any implementation prompt. | A first implementation phase may create and independently review the evidence package. All record gates remain prerequisites to consumer invocation and the 21-case run. | Enables a bounded evidence-package-first prompt without authorizing the pilot itself. |
| Coverage delta and lock/runtime proof were incomplete. | The revision includes a 21-case coverage map, exact frozen blob/lock digests, proven declarations, and remaining runtime unknowns. | Narrows the incremental claim and makes freeze admission testable. |
| One repair-and-replay was general. | Baseline must run first. At most one bounded seam repair and one complete replay are allowed; oracle semantics and mutation axes cannot be tuned after results. | Prevents benchmark gaming and maintenance creep. |

## 2. Scope, non-goals, claim ceiling, and hypotheses

The pilot evaluates exactly three claims:

1. **P1:** receipt-backed GitHub security evidence is sufficient for PCC to display a complete project-security decision only when the receipt subject, project identity, and PortfolioTruth producer repository/revision are mutually bound.
2. **P2:** one MCPAudit-shaped result is admissible as a fresh mcp-trust per-server fixture grade only when its evidence, receipt, persisted scan, result, and static snapshot agree.
3. **P3:** one RecoveryAnchorV1 bundle supports BridgeDB recovery readiness only when it is internally valid and current for the claimed source.

The primary corpus is exactly:

- 3 valid controls, one per path.
- 18 one-axis mutations: missing, stale, masked, contradictory, unsupported, and identity/head-mismatched for each path.
- 21 total primary cases.

Correlated fields may change together only when the case manifest declares them as the necessary closure of one semantic mutation. Favourability-bearing payload—risk, grade, or logical claim value—must not be improved by a mutation.

### Non-goals and preserved exclusions

- No live BridgeDB, real portfolio, real MCP host, credential, scheduler, participant, buyer, or external service.
- No open PR head as fixture evidence.
- No AIGCCore open-stack work, OPERANT #43, or local-only protocol-auditor claim.
- No global mcp-trust publication readiness, refresh publication, deployment, live scan, or scheduler readiness.
- No infrastructure mutation, ApprovalEffect, Context Attestation, Shadow Credential work, workshops, commercial product, distribution experiment, benchmark service, dashboard, shared evidence store, or adapter marketplace.
- No assertion of factual observation correctness, server safety, authorization, production readiness, portfolio completeness, scheduler health, or generality beyond the frozen contracts and admitted corpus.

### Claim ceiling

A passing pilot proves only:

> Across the admitted 21 synthetic cases, the frozen or single-repair consumers did not grant more positive-claim authority than the independently frozen evidence ceilings allowed.

It does not prove the consumers safe in general or the source evidence factually correct.

### Falsifiable hypotheses

- **H-CONTROL:** all 3 controls normalize to `(STRONG, VALID)`.
- **H-P1:** all 6 P1 mutations are strictly weaker than P1-C; P1-06 cannot remain complete when receipt subject, project identity, or producer head disagree.
- **H-P2:** all 6 P2 mutations are strictly weaker than P2-C under per-server fixture-grade admissibility; global `publication_ready` has no effect on normalization.
- **H-P3:** all 6 P3 mutations are strictly weaker than P3-C; a valid but source-mismatched anchor cannot remain recovery-ready.
- **H-NOOP:** every evidence-equivalent representation change preserves authority, disposition, and raw reason-code multiset.
- **H-DET:** repeated evaluation under each admitted environment produces identical normalized results and canonical hashes.
- **H-IND:** oracle ceilings remain unchanged when consumer outputs and expected values from consumer tests are withheld from adjudicators.

H-CONTROL through H-DET failures are pilot `FAIL`s. Inability to establish H-IND is an `ABORT`.

## 3. Exact frozen paths and decision surfaces

| Path | Producer and evidence contract | Frozen consumer | Exact consumer input and decision surface | Freeze posture |
|---|---|---|---|---|
| P1 | GithubRepoAuditor `fd61f1c06643c4431460e27aa9210ff8b931ef1d`; PortfolioTruth `0.11.0`; `GitHubSecurityCoverageReceiptV1`; `portfolio_attention.v3` | PortfolioCommandCenter `1139cfb9bb1e8d005699f854df368583960e245c` | `P1ConsumerInputV1 = {raw receipt, one-project snapshot}` → project `securityCoverageState` and Risk Security overall state. PCC owns subject/repository/head binding. | Revisions and sources resolve. Current PCC does not enforce the full pair binding; this is baseline behavior, not a spec exception. |
| P2 | `mcp-audits==2.4.0`; tag commit `9484d8bb1b059ce48f77015c4a84561675517a77`; serialized MCPAudit-shaped evidence | mcp-trust `a30be69132802d2b24157066fa4dc125e8edfdca`; `EngineResult`, receipt format 1, `RefreshCandidateV1` | `MCPTrustPerServerFixtureAdmissibilityV1`: candidate structural validity plus one server’s state, fresh grade, receipt/scan binding, and static-snapshot inclusion. | Fully bounded to deterministic fixture candidates. `publication_ready` is ignored and expected to be false. |
| P3 | `RecoveryAnchorV1`; source schema 22 | bridge-db `b47e5428b0f512c5e4ab87212acdd1d844b365b0` | `BridgeRecoveryReadinessProjection@b47e5428`: `state`, `ready`, `source_current`, `recovery_readback`, integrity fields, permissions, and errors. | Revision and contract resolve. Live anchor state is excluded. |

Frozen Git objects remain locally resolvable. Current remote heads, open PRs, worktree ownership, and leases are not freeze evidence and must be freshly captured by `OwnershipPreflightV1` before later writes.

## 4. Non-vacuous evidence and verdict orders

### 4.1 Evidence order

For each case, normalized evidence quality is:

\[
E = \{0,1\}^{6}
\]

with coordinates:

\[
(present,\ current,\ visible,\ consistent,\ supported,\ bound)
\]

and `0 < 1` on every coordinate.

The valid control is:

\[
e_C=(1,1,1,1,1,1)
\]

Each primary mutation sets exactly its named coordinate to `0`; its declared closure may update correlated representations but no second semantic coordinate:

- missing → `present=0`
- stale → `current=0`
- masked → `visible=0`
- contradictory → `consistent=0`
- unsupported → `supported=0`
- identity/head mismatch → `bound=0`

Product order defines:

\[
e \preceq_E e' \iff \forall k,\ e_k \le e'_k
\]

Therefore every mutation satisfies `e_m ≺E e_C`, while different one-axis siblings are normally incomparable. This prevents “everything degraded” from being treated as one undifferentiated scalar.

### 4.2 Verdict order

A normalized verdict is:

```text
{
  authority: BLOCKED | NONAUTHORITATIVE | CONDITIONAL | STRONG,
  disposition:
    VALID | PARTIAL | MISSING | STALE | MASKED |
    CONTRADICTORY | UNSUPPORTED | MISBOUND,
  reason_codes: sorted unique strings
}
```

Authority order is:

\[
BLOCKED < NONAUTHORITATIVE < CONDITIONAL < STRONG
\]

For verdicts \(v=(a,d)\) and \(w=(a',d')\):

\[
v \preceq_V w
\]

iff either:

1. \(a < a'\), or
2. \(a=a'\) and \(d=d'\).

Different dispositions at the same authority are incomparable. A lower authority is always weaker regardless of disposition.

Consequences:

- All controls must be `(STRONG, VALID)`.
- No primary mutation may be `STRONG` or `CONDITIONAL`.
- A hard rejection may be below a `NONAUTHORITATIVE` ceiling.
- If the consumer stays at the ceiling’s authority, its disposition must match.
- Exact reason conformance is checked separately so a wrong diagnostic cannot hide behind an over-restrictive authority result.

### 4.3 Frozen raw-to-normalized mappings

- **P1:** bound complete → `STRONG`; verified partial → `CONDITIONAL`; stale/unknown → `NONAUTHORITATIVE`; structural rejection → `BLOCKED`.
- **P2:** bound fresh per-server fixture grade → `STRONG` even though `publication_ready=false`; missing/stale/masked → `NONAUTHORITATIVE`; invalid schema, contradiction, or binding → `BLOCKED`.
- **P3:** verified and source-current → `STRONG`; missing/stale → `NONAUTHORITATIVE`; invalid integrity/schema/binding material → `BLOCKED`.

An A–F grade is payload, not authority. A strongly evidenced F grade remains `STRONG`.

## 5. Conservation and metamorphic relations

For path \(i\), valid control \(C_i\), mutation \(T_m\), frozen consumer \(F_i\), normalized mapping \(N_i\), and independently adjudicated ceiling \(O(x)\):

1. **Control adequacy**

   \[
   N_i(F_i(C_i))=(STRONG,VALID)
   \]

2. **Strict evidence degradation**

   \[
   T_m(C_i)\prec_E C_i
   \]

3. **Strict verdict downgrade**

   \[
   N_i(F_i(T_m(C_i)))\prec_V N_i(F_i(C_i))
   \]

4. **Oracle ceiling**

   \[
   N_i(F_i(T_m(C_i)))\preceq_V O(T_m(C_i))
   \]

5. **Disposition conformance**

   At equal ceiling authority, observed disposition must equal the independently assigned mutation disposition. Raw reasons must contain the predeclared accepted reason family.

6. **No-op preservation**

   If \(R(C_i)\equiv_E C_i\), the complete normalized verdict and raw reason-code multiset must be identical.

7. **Mutation locality**

   The declared changed-field closure must equal the complete semantic delta. Undeclared differences abort the case.

8. **Replay**

   Same case, freeze, clock, environment, and dependency digests must produce the same canonical result hash.

A mutation failing independent claim-criticality review is removed from the primary set and therefore causes `ABORT`; it cannot be silently weakened into a no-op after consumer output is seen.

## 6. Revised 21-case matrix

`Covered` means an equivalent downstream assertion exists at the frozen path. `Partial` means an adjacent predicate or lower-level failure exists but not the complete case. `Cross` means the assertion genuinely spans producer and consumer responsibility.

| ID | Exact control or one-axis mutation closure | Required normalized ceiling | Required relation | Existing coverage |
|---|---|---|---|---|
| P1-C | Valid raw ReceiptV1 and matching one-project snapshot; all providers observed; fresh; producer repository/commit and project repo agree | `(STRONG, VALID)` | control | Covered |
| P1-01 | Remove one required provider from raw receipt and projected security block as one absence closure | `(NONAUTHORITATIVE, MISSING)` | `< P1-C` | Covered |
| P1-02 | Move evaluation beyond 24h; raw `produced_at` stays fixed; projected `receipt_state` and `coverage_state` become stale | `(NONAUTHORITATIVE, STALE)` | `< P1-C` | Covered |
| P1-03 | Replace one required provider count with explicit `REDACTED` sentinel in receipt and projection; oracle retains the hidden value | `(NONAUTHORITATIVE, MASKED)` | `< P1-C` | Partial |
| P1-04 | Keep aggregate `coverage_state=complete` while one provider declares incomplete pagination; all fields remain present and supported | `(NONAUTHORITATIVE, CONTRADICTORY)` | `< P1-C` | Partial |
| P1-05 | Change receipt and projected receipt schema from ReceiptV1 to ReceiptV2; no other field changes | `(NONAUTHORITATIVE, UNSUPPORTED)` | `< P1-C` | Covered |
| P1-06 | Raw receipt remains keyed to subject A and frozen producer head; snapshot project identity becomes subject B | `(NONAUTHORITATIVE, MISBOUND)` | `< P1-C` | **Cross** |
| P2-C | Deterministic fixture candidate; structural valid; result `fresh`; non-null grade; format-1 receipt; persisted scan/result/snapshot agree | `(STRONG, VALID)` | control | Covered |
| P2-01 | Use the frozen missing-receipt creation path: no receipt is emitted and grade is withheld | `(NONAUTHORITATIVE, MISSING)` | `< P2-C` | Covered |
| P2-02 | Evaluate the unchanged candidate exactly at `expires_at` | `(NONAUTHORITATIVE, STALE)` | `< P2-C` | Covered |
| P2-03 | Put the server under reviewed masking; withhold grade, receipt, scan ID, drift, and snapshot row | `(NONAUTHORITATIVE, MASKED)` | `< P2-C` | Covered |
| P2-04 | Change `fresh_grade` only and rebind artifact/manifest hashes; persisted scan, receipt, and snapshot remain unchanged | `(BLOCKED, CONTRADICTORY)` | `< P2-C` | Covered |
| P2-05 | Change receipt `format_version` from 1 to 2 and rebind artifact hashes | `(BLOCKED, UNSUPPORTED)` | `< P2-C` | Partial |
| P2-06 | Change receipt `scan_id` or `server_slug` to another syntactically valid identity; persisted scan/result remain unchanged | `(BLOCKED, MISBOUND)` | `< P2-C` | Partial |
| P3-C | Exact two-file private bundle; schema 22; digest, byte size, SQLite integrity, semantic readback, source fingerprint, and permissions agree | `(STRONG, VALID)` | control | Covered |
| P3-01 | Source remains; anchor bundle is absent | `(NONAUTHORITATIVE, MISSING)` | `< P3-C` | Covered |
| P3-02 | Update one synthetic source row after anchor creation, preserving table and row count | `(NONAUTHORITATIVE, STALE)` | `< P3-C` | Covered |
| P3-03 | Replace required manifest SHA-256 with explicit `REDACTED_SHA256`; database remains unchanged | `(BLOCKED, MASKED)` | `< P3-C` | Partial |
| P3-04 | Change manifest `backup_bytes` to a different nonnegative integer; artifact remains unchanged | `(BLOCKED, CONTRADICTORY)` | `< P3-C` | Partial |
| P3-05 | Change SQLite `user_version` and manifest source schema from 22 to 23; recompute byte/digest bindings | `(BLOCKED, UNSUPPORTED)` | `< P3-C` | Covered |
| P3-06 | Pair source A with an internally valid, self-consistent schema-22 anchor created from synthetic source B | `(NONAUTHORITATIVE, MISBOUND)` | `< P3-C` | Partial |

All 18 ceilings must be independently adjudicated even when the resulting authority/disposition repeats another case.

## 7. Read-only coverage-delta analysis

### Classification rule

- **Covered:** same semantic mutation and downstream decision are directly asserted.
- **Partial:** code or tests cover an adjacent field, integrity check, or inverse transformation, but not the exact primary sibling and normalized relation.
- **Cross:** the invariant cannot be established by either existing local contract alone.

### P1

- Covered control: `distinguishes a complete zero-finding observation from unknown coverage`.
- Covered missing: `does not treat an incomplete provider set as a complete zero scan`.
- Covered stale: fresh-receipt parameterization plus all-stale overall-state assertion.
- Partial masked: changed count types fail closed, but no explicit redaction-sentinel case exists.
- Partial contradictory: the selector rejects incomplete provider observations, but no exact complete-aggregate/incomplete-detail sibling pins the cross-field contradiction.
- Covered unsupported: `fails closed on an unsupported complete-coverage receipt schema`.
- Cross misbinding:
  - GithubRepoAuditor tests pin receipt producer commit against the expected canonical commit.
  - Producer projection joins receipt entries by repository.
  - The projected `SecurityFields` drops `repo_full_name` and producer commit.
  - PCC’s displayed decision does not restore or assert that binding.

### P2

- Covered control: `test_deterministic_fixture_candidate_is_immutable_and_reviewable`.
- Covered missing: `test_missing_receipt_is_explicit_and_not_fresh`.
- Covered stale: `test_exact_expiry_boundary_is_stale`.
- Covered masked: `test_masked_grade_is_withheld_from_results_and_snapshot`.
- Covered contradictory: rebound fresh-grade and static-snapshot binding tests.
- Partial unsupported: verifier explicitly requires receipt format 1, but no dedicated format-2 sibling asserts the per-server normalized disposition.
- Partial misbinding: verifier compares receipt/result server and scan identities, but no dedicated exact scan-ID/server sibling pins the complete relation.

### P3

- Covered control: private, disposable recovery verification.
- Covered missing: recovery-anchor CLI fails closed on `anchor_missing`.
- Covered stale: insert and same-count update tests both produce `source_changed_since_anchor`.
- Partial masked: missing/type/digest checks exist, but no explicit redaction sentinel.
- Partial contradictory: byte/digest tampering is covered, but not a manifest-only `backup_bytes` contradiction with unchanged artifact.
- Covered unsupported: schema 23 with rebound digest is rejected.
- Partial misbinding: source-change tests exercise fingerprint inequality, but no second-subject anchor fixture proves the distinct binding axis.

### Delta result

Primary mutations:

- Covered: **10/18**
- Partial: **7/18**
- Genuinely cross-contract: **1/18**
- Unmapped: **0/18**

Controls: **3/3 covered**.

The defensible incremental claim is the shared independent oracle plus P1-06’s dropped producer/subject binding. Existing path-local coverage cannot be represented as novel pilot functionality.

## 8. Independent oracle and anti-circularity

### Ground truth sources

- **P1:** an independent synthetic ledger containing receipt producer repository/commit, cohort repositories, provider observations, project identity, timestamps, pagination, and counts. PCC code and test expectations are not ground truth.
- **P2:** a fixed synthetic grade payload plus independently declared receipt/result/scan/snapshot identities. The oracle does not run or reproduce the mcp-trust grading rubric.
- **P3:** an independently declared logical SQLite dataset and explicit synthetic source identity. It does not call BridgeDB’s semantic-fingerprint implementation to establish expected identity.

### Adjudication

1. Freeze candidate source and consumer revisions before adjudication.
2. Two reviewers independently classify all 21 evidence vectors, control relations, dispositions, and ceilings while blinded to consumer output.
3. Both reviewers must attest that consumer tests were used only for feasibility/coverage, never expected truth.
4. Initial Cohen’s κ must be at least `0.80`.
5. Resolve disagreements only against the positive claim, producer contracts, and ratified boundary decisions.
6. A third independent reviewer adjudicates unresolved entries.
7. Require 21/21 final agreement.
8. Seal the oracle digest before any adapter invokes a consumer.

One unresolved case causes `ABORT`. More than two initially ambiguous cases after one clarification round triggers the kill gate.

### Leakage controls

- Oracle files and mutation labels are not passed to adapters or consumers.
- Consumer-visible IDs, filenames, ordering, and padding are opaque.
- Raw-to-normalized authority mapping is sealed before output exists.
- Runner-side comparison may use the sealed oracle only after raw adapter output is committed.
- Consumer output cannot alter case family, evidence relation, ceiling, or accepted reason family.

## 9. Fixture admissibility and safety

Each fixture must be:

- Fully synthetic or derived from an explicitly licensed, public-safe fixture.
- Bound to reserved identities and domains such as `example.invalid`.
- Free of live PortfolioTruth data, BridgeDB rows, raw private MCP schemas, user paths, credentials, cookies, tokens, participants, buyers, and private repository content.
- Accompanied by provenance, generator revision, rights classification, byte count, and SHA-256.
- Secret-scanned with zero unallowlisted findings.
- Explicit about redaction through inert sentinels.
- Immutable after admission.
- Rejected if its mutation closure changes more than the named semantic axis.
- Rejected if mutation/oracle labels leak into consumer-visible content.

Current live PortfolioTruth, current BridgeDB, ignored local mcp-trust candidate artifacts, and open-PR data are inadmissible.

## 10. Determinism and platform constraints

- Network, DNS, package download, external connector access, subprocess MCP launch, and live scans are denied during the pilot.
- P2 consumes serialized evidence and candidate artifacts; it never calls `MCPAuditEngine.scan`.
- Time is injected in UTC:
  - P1 freshness boundary is 24 hours.
  - P2 exact expiry is stale.
- Locale `C`, timezone `UTC`, UTF-8, fixed random seed, fixed Python hash seed, and canonical JSON are mandatory.
- Future execution may write only inside one isolated disposable run root.
- Same-environment replay must be byte-identical after removing only predeclared run IDs and timestamps.
- Cross-environment replay requires identical normalized verdicts, reason-code sets, relations, and canonical result hashes. Raw SQLite file bytes need not match.
- P3 requires honest POSIX private-permission semantics. An environment unable to represent them is `UNSUPPORTED`; it cannot emulate green.
- Any undeclared source, schema, runtime, lock, dependency, or environment drift aborts before consumer invocation.
- Package-manager verification in the evidence phase must be offline, use isolated disposable HOME/cache/tool-state locations, and leave repositories unchanged.

## 11. Freeze facts proven now versus prerequisites

All listed hashes were computed directly from frozen committed blobs.

### P1 candidate freeze facts

GithubRepoAuditor:

- `pyproject.toml`: `f3cdf5c34df5be4b3b8d6ea52facb9cff76ee20708af3cffc4d69c20bf0a0b9c`
- `uv.lock`: `1b4d79dcedd731ddc0b35a01e8aa1672b0287afc6391d7aafe44223a130d21a6`
- `requirements.txt`: `22cc6c4cd15e7bd0702d18f1484930f6f216342faac1b58ab2c41efad42c9337`
- Contract source digests:
  - `github_security_coverage.py`: `84c72d8…b448b39`
  - `portfolio_truth_reconcile.py`: `26ac220f…f0a71c`
  - `portfolio_truth_types.py`: `b99383bc…fe0e2e`
- Declared runtime: Python `>=3.11`; exact patch is not pinned.

PortfolioCommandCenter:

- `package.json`: `5fe0a83aee75da01174fbb2472adc41fa4a1760cc9df07313a5946eb17969f9b`
- `pnpm-lock.yaml`: `ce22d21ebc110bf4d5f75858e36556c9b9e9911a9399be21c1c83eff3f4b2820`
- `Cargo.toml`: `db446ccead7b0ddb524515d82486641cbc2288f9b90356075660626679a1b948`
- `Cargo.lock`: `c963d4103c730eddf6fe269f8b941623d1e70b7c4cc6ab9b71ac0cdf3c7b8445`
- Contract source digests:
  - `types.ts`: `687975d8…2e7798`
  - `validation.ts`: `bacd0786…b5832b`
  - `RiskSecurity.tsx`: `ca8884e2…0bee1`
- Declared package manager: pnpm `11.5.2`.
- Node version and Rust toolchain are unpinned; Rust edition 2021 is not a toolchain version.

### P2 candidate freeze facts

MCPAudit:

- `.python-version`: `3.11`
- `pyproject.toml`: `11390acdc5225dd1fcde052b3e08c56eb4ef3ddab5fd81316a48c4787ef6777b`
- `uv.lock`: `b68639c0bc8746066d8da1461d27bbbd240454beb368b6cdae9300adc2e454af`
- Contract source:
  - `engine.py`: `60c1e125…de9181`
  - `models.py`: `356613e7…14a50`
- Package version: `2.4.0`; Python `>=3.11`.

mcp-trust:

- `pyproject.toml`: `f3bac0415dbc201ddc6de73fffc207b651f8eb395674d2f9a0574c4b3e2e7c3d`
- `uv.lock`: `2bfd0d8f432abf289644b2fdca2e17b8cd30a1937dd36d57dfdb5a313a893609`
- Contract source:
  - `engine/base.py`: `dc1e6b2f…7c5c3`
  - `engine/mcpaudit.py`: `b717493b…7093a`
  - `refresh.py`: `d54ed030…cda6`
- Declared Python: `>=3.11`; exact patch unpinned.
- Locked MCPAudit artifacts:
  - wheel: `sha256:5a2e18c9271d381a5d5482f7baf2bcd64cd52bdbdfd14cc501c32334b0aac66a`
  - sdist: `sha256:a7dd4733d3413d15fabcd2d8aa763b2b95b237b8af99b50d507b98a716a7641d`

### P3 candidate freeze facts

- `.python-version`: `3.12`
- `pyproject.toml`: `2d2d6fd5128603e2757a6952f21c06b6eb2b7493b8669e325de964f27692a595`
- `uv.lock`: `f300fccebaa2a5e68ceb3f98ced5bb115038dd6bfc19c8f93829d64d3c8d736f`
- Contract source:
  - `recovery.py`: `4a673396…22a356`
  - `db.py`: `96ad9310…e76f5`
  - `tools/health.py`: `565955fc…1660b`
- Declared Python: `>=3.12`; `.python-version` selects the 3.12 family.
- Contract schema: 22.

### Still required for admitted freezes

- Exact runtime patch versions.
- Actual pnpm, Node, Rust, Cargo, Python, and uv executable versions.
- Offline lock/manifest consistency verification.
- Installed artifact hashes and confirmation that the locked MCPAudit bytes match the admitted environment.
- OS, architecture, libc where relevant, SQLite version, filesystem, and permission semantics.
- Environment isolation and network-denial evidence.
- Full source-file inventory chosen by each path owner.
- Independent review and sealed `FreezeReceiptV1` records.

The hashes above are candidate values, not admitted freeze receipts.

## 12. Harness and machine-readable result contracts

Version 1 has exactly three adapters.

### `EvidenceConservationCaseV1`

Consumer-visible runner input:

- `schema`
- `case_id`
- `family_id`
- `path_id`
- `freeze_receipt_id`
- `fixture_artifact_refs`
- `fixed_clock`
- `environment_profile_id`
- `opaque_subject_id`
- `consumer_revision`
- `input_sha256`

It contains no mutation name, expected verdict, ceiling, or oracle reference.

### `EvidenceConservationPlanV1`

Runner-only:

- control/sibling relationship
- mutation axis
- complete changed-field closure
- pre/post artifact digests
- expected evidence relation
- oracle entry reference
- accepted raw reason families

### Adapter contract

Input:

- consumer-visible case
- read-only fixture resolver
- injected clock
- isolated runtime context

Output:

- unmodified raw consumer state
- raw warnings/errors/reason codes
- referenced artifact digests
- access-attempt receipt
- exception information, if any

Adapters may decode, invoke, and extract. They may not reproduce grading, security-provider validation, semantic fingerprinting, or oracle rules.

For P2, `publication_ready` may be retained in raw diagnostics but is forbidden from influencing normalized authority.

### `EvidenceConservationResultV1`

Required fields:

- schema/run/case/path/repetition/environment identities
- input, freeze, fixture, adapter, and raw-output digests
- raw state and sorted reason codes
- normalized authority and disposition
- observed evidence and verdict relations
- oracle ceiling
- control verdict reference
- strict-downgrade, ceiling, disposition, locality, and determinism booleans
- access receipt
- `PASS | FAIL | ABORT`
- bounded non-sensitive diagnostics

### `EvidenceConservationRunV1`

Required fields:

- exact 21-case inventory
- 420 primary evaluation inventory
- counts by path, mutation, authority, and outcome
- no-op, near-miss, leakage, and replay results
- seven schema-family record references
- oracle and environment digests
- repair cycle number `0 | 1`
- aggregate `PASS | FAIL | ABORT | KILL_RECOMMENDED`

## 13. Supplemental tests

### Positive

- Three valid controls.
- One adverse but fully evidenced mcp-trust grade proving that grade favourability is not authority.

### Negative

- One malformed case envelope per path must abort before consumer invocation.
- One consumer exception per path must become `ABORT`, never `UNKNOWN` or `PASS`.

### No-op, minimum two per path

- P1: JSON key ordering; additive unknown metadata.
- P2: equivalent finding/tool ordering with bindings recomputed; equivalent UTC spelling.
- P3: manifest key ordering; identical source at a URI-sensitive path.

### Near-miss, minimum two per path

- P1: just inside versus outside 24 hours; mask optional metadata versus a required count.
- P2: immediately before versus exactly at expiry; change optional non-authoritative metadata versus receipt format.
- P3: identical logical source versus same-count row update; private versus group-readable permissions.

### Mutation leakage

- Randomize case IDs and filenames.
- Reorder cases and equalize superficial size cues.
- A metadata-only classifier must not exceed `0.50` macro-F1 or the majority baseline by more than `0.10`.

## 14. Quantitative gates

### Evidence-package admission

Before any consumer invocation:

- 29/29 required records exist.
- 29/29 have `admission_status=ADMITTED`.
- Every review hashes the admitted content.
- 3/3 freezes match available environments.
- 21/21 fixtures pass rights, privacy, secret, contamination, and locality checks.
- Oracle κ ≥ `0.80` initially and 21/21 final agreement.
- Coverage map contains 21/21 cases and preserves the `10 covered / 7 partial / 1 cross` primary classification unless a fresh frozen-source review justifies a signed revision.
- No required field is `UNKNOWN`.

### Pilot pass

- 3/3 controls are `(STRONG, VALID)` in every repetition and environment.
- 18/18 mutations are strictly below their control.
- 18/18 are at or below their ceiling.
- 18/18 dispositions/reason families conform.
- 0 schema, locality, contamination, or mutation-leakage violations.
- At least 6/6 no-ops preserve complete normalized verdicts and reasons.
- At least 6/6 near-misses match predeclared boundaries.
- `21 cases × 10 repeats × 2 environments = 420/420` deterministic primary evaluations.
- Zero network attempts, live-system reads, undeclared subprocesses, secret findings, or writes outside the isolated run root.

### Pilot fail

Any of:

- A control below `STRONG`.
- A mutation at `CONDITIONAL` or `STRONG`.
- A verdict above its ceiling.
- Equal-authority disposition mismatch.
- No-op drift.
- Consumer-output-driven oracle relabelling.
- Oracle data visible to an adapter or consumer.

### Abort

Any of:

- Missing or unadmitted prerequisite.
- Revision, source, lock, runtime, environment, schema, or fixture digest mismatch.
- Rights or secret status unknown.
- Consumer crash or incomplete case.
- Network or live-system access.
- Platform unable to execute a frozen contract honestly.
- Any unplanned source, repository, or system mutation.

### Kill

- Fewer than two paths retain the shared invariant.
- More than two cases remain oracle-ambiguous after one resolution round.
- Any path cannot produce a rights-safe offline `STRONG` control.
- An adapter must reimplement consumer semantics.
- Fresh coverage review finds all 18 mutations independently asserted and no shared-oracle delta.
- Leakage exceeds the threshold.
- The design requires a live host, credential, scheduler, participant, dashboard, shared store, or fourth adapter.

A conservation failure is a scientific `FAIL`, not a kill condition.

## 15. Exact prerequisite record schemas and admission gates

There are seven schema types and 29 record instances.

### Common closed-record envelope

Every record is a closed JSON object with:

- `schema: string`
- `record_id: string`
- `spec_sha256: 64-hex string`
- `created_at_utc: RFC3339 UTC string`
- `producer: {actor_id: string, role: string}`
- `supersedes: string | null`
- `body: type-specific closed object`
- `content_sha256: 64-hex string`
- `reviews: array`
- `admission_status: CANDIDATE | ADMITTED | REJECTED`

Each review is closed:

- `reviewer_id`
- `independent_from: string[]`
- `decision: ADMIT | REJECT`
- `reviewed_at_utc`
- `reviewed_content_sha256`
- `rationale`

`content_sha256` hashes RFC 8785 canonical JSON over the envelope through `body`, excluding `content_sha256`, `reviews`, and `admission_status`. Admission requires all admitting reviews to reference that exact hash.

### 15.1 `BoundaryDecisionV1` — 1 record

Body:

- `strict_downgrade: REQUIRED`
- `pcc_binding_owner: PORTFOLIO_COMMAND_CENTER`
- `p2_decision_surface: PER_SERVER_FIXTURE_GRADE_ADMISSIBILITY`
- `p2_exclusions`: exact set of:
  - `GLOBAL_PUBLICATION_READY`
  - `REFRESH_PUBLICATION`
  - `LIVE_SCAN`
  - `SCHEDULER_READINESS`
- `approval_evidence`:
  - `thread_id`
  - `turn_id`
  - `message_sha256`
- `contradictions: []`

Gate:

- Values exactly match the ratified decisions.
- Approval evidence resolves to the operator message.
- No current source contradiction.
- One independent reviewer admits the transcription.

### 15.2 `FreezeReceiptV1` — 3 records

Body:

- `path_id: P1 | P2 | P3`
- `components[]`, each containing:
  - `role: PRODUCER | CONSUMER`
  - `repository`
  - `revision`
  - `contract_ids[]`
  - `source_files[{path, sha256}]`
  - `manifests[{path, sha256, format}]`
  - `locks[{path, sha256, format}]`
  - `runtime_declarations[{path, sha256, constraint}]`
- `artifacts[{name, version, kind, sha256}]`
- `resolved_environment`:
  - `os`
  - `architecture`
  - `runtime_versions`
  - `package_manager_versions`
  - `sqlite_version`
  - `filesystem_semantics`
- `lock_consistency`:
  - `status: VERIFIED | FAILED`
  - `verifier`
  - `receipt_sha256`
- `clock_contract`
- `all_objects_resolve: boolean`

Gate:

- Exact revision resolution.
- All selected source/manifest/lock hashes match.
- Runtime satisfies every declaration.
- Locks verify offline without repository writes.
- Required artifacts match locked hashes.
- Environment supports the path honestly.
- No `UNKNOWN`, `FAILED`, or unresolved object.
- Independent reviewer distinct from the freezer admits it.

### 15.3 `OracleAdjudicationV1` — 1 record

Body:

- `oracle_id`
- `freeze_receipt_ids[3]`
- `entries[21]`, each containing:
  - `case_id`
  - `path_id`
  - `control_case_id`
  - six-bit evidence vector
  - `evidence_relation`
  - `authority_ceiling`
  - `disposition`
  - `accepted_reason_families[]`
  - `claim_critical`
  - `rationale`
  - `contract_refs[]`
- `reviewers[2]`
- `blindness_attestations[2]`
- `agreement`:
  - `method: COHENS_KAPPA`
  - `initial_value`
  - `initial_disagreements[]`
- `adjudicator: object | null`
- `final_agreement_count`
- `consumer_outputs_seen: false`
- `sealed_at_utc`
- `oracle_sha256`

Gate:

- Exactly 21 unique cases.
- Three controls are strong.
- Every mutation is strict evidence degradation and has an explicit ceiling.
- κ ≥ `0.80`.
- 21/21 final agreement.
- No consumer output seen.
- No unresolved case.
- Oracle sealed before invocation.

### 15.4 `FixtureAdmissibilityV1` — 21 records

Body:

- `case_id`
- `path_id`
- `family_id`
- `control_case_id`
- `fixture_kind: CONTROL | MUTATION`
- `artifacts[{ref, media_type, bytes, sha256}]`
- `generator`:
  - `repository`
  - `revision`
  - `config_sha256`
- `provenance`:
  - `source_class`
  - `source_ref`
  - `license`
  - `derivation`
- `rights`:
  - `classification`
  - `reviewer`
  - `admissible`
- `privacy`:
  - `synthetic_only`
  - `reserved_identities_only`
  - `real_data_present`
- `secret_scan`:
  - `scanner`
  - `ruleset_sha256`
  - `findings`
  - `allowlist[]`
- `mutation_locality`:
  - `axis`
  - `parent_sha256`
  - `changed_fields[]`
  - `before_vector`
  - `after_vector`
  - `favourability_payload_unchanged`
- `contamination`:
  - `opaque_names`
  - `oracle_fields_visible`
  - `mutation_label_visible`

Gate:

- Artifact digests resolve.
- Rights admissible.
- Synthetic/reserved identities only.
- No real data.
- Zero unallowlisted secret findings.
- Exactly one declared evidence axis changes for mutations.
- No oracle or mutation metadata is consumer-visible.
- Independent reviewer distinct from fixture generator admits it.

### 15.5 `DeterminismProfileV1` — 1 record

Body:

- `profiles[2]`, each containing:
  - `profile_id`
  - `os`
  - `architecture`
  - `runtimes`
  - `package_managers`
  - `sqlite_version`
  - `timezone: UTC`
  - `locale: C`
  - `encoding: UTF-8`
  - `fixed_clock`
  - `random_seed`
  - `python_hash_seed`
  - `environment_allowlist`
  - `filesystem_semantics`
  - `network_denial`
  - `subprocess_policy`
  - `writable_roots`
  - `canonicalization_exclusions`
  - `repeat_count: 10`
- `freeze_receipt_ids[3]`
- `preflight_results`
- `profile_sha256`

Gate:

- Exactly two clean supported profiles.
- Both satisfy all three freezes.
- P3 permission semantics are real, not emulated.
- Network denial and write containment have preflight evidence.
- Repeat count and clock are fixed.
- No undeclared environment input.
- Independent admission.

### 15.6 `CoverageDeltaV1` — 1 record

Body:

- `freeze_receipt_ids[3]`
- `entries[21]`, each containing:
  - `case_id`
  - `classification: COVERED | PARTIAL | CROSS_CONTRACT`
  - `source_tests[]`
  - `asserted_surface`
  - `missing_assertion`
  - `cross_contract_delta`
  - `reviewer_rationale`
- `primary_counts`:
  - `covered`
  - `partial`
  - `cross_contract`
- `unmapped_count`
- `new_claim`
- `coverage_sha256`

Gate:

- Exactly 21 entries.
- Every source reference resolves at the corresponding freeze.
- Primary counts initially equal `10/7/1`.
- Unmapped count is zero.
- New claim is limited to the common oracle and P1 binding seam.
- Independent reviewer admits the equivalence judgments.

### 15.7 `OwnershipPreflightV1` — 1 record

Body:

- `observed_at_utc`
- `fresh_for_seconds`
- `target`:
  - `repository`
  - `worktree`
  - `branch`
  - `head_sha`
  - `base_ref`
- `git_state`:
  - `tracked_changes[]`
  - `untracked_changes[]`
  - `preserved_paths[]`
- `lease`:
  - `state: HELD | AVAILABLE | CONFLICT`
  - `owner`
  - `expires_at_utc`
- `peer_preflight`:
  - `checker`
  - `receipt_sha256`
  - `result`
- `allowed_writes[]`
- `forbidden_effects[]`
- `publication`:
  - `allowed: false`
  - `remote_effects: false`

Gate:

- Exact repository/worktree/branch/head.
- Observation no older than 30 minutes at first write.
- No lease or ownership conflict.
- Dirty and untracked work explicitly preserved.
- Peer preflight passes.
- Writes limited to the named evidence-package paths.
- No push, PR, issue, deployment, global configuration, BridgeDB, or scheduler effect.

## 16. Specification completion versus record completion

### Complete now

- The three boundary decisions are settled.
- Three paths, three controls, and eighteen mutations are fixed.
- Evidence and verdict orders are formal and non-vacuous.
- P1 and P2 decision surfaces are unambiguous.
- All mutation closures and ceilings are specified.
- Coverage delta is classified.
- Candidate source and lock digests are known.
- Record schemas and gates are defined.
- No remaining design choice prevents an evidence-package prompt.

### Not complete now

- No canonical spec artifact/digest exists.
- No prerequisite record is admitted.
- No independent oracle adjudication has occurred.
- No 21-fixture corpus exists.
- No exact two-environment profile exists.
- No ownership target is freshly preflighted.
- No consumer has been invoked.
- No baseline result or repair exists.

Specification completion does not imply evidence-package completion, pilot authorization, or pilot success.

## 17. Smallest authorized first implementation phase

The first phase is `EVIDENCE_PACKAGE_ONLY`.

It may:

1. Select one isolated worktree and create an admitted `OwnershipPreflightV1`.
2. Persist this specification canonically and bind its SHA-256.
3. Create the 29 prerequisite records.
4. Generate the 21 synthetic fixtures without invoking any consumer.
5. Perform offline schema, digest, locality, rights, privacy, secret, contamination, and deterministic-generation checks.
6. Obtain the required independent reviews.
7. Report which gates passed or failed.

It must not:

- Invoke PCC, mcp-trust, or BridgeDB consumer logic.
- Execute any of the 21 pilot cases.
- Run MCPAudit scans.
- Access live systems or network services.
- Modify any consumer or producer.
- Push, open a PR, deploy, schedule, publish, or write BridgeDB.
- Convert failed or unknown records into admitted records.

This phase always stops after the evidence-package report. Even 29/29 admitted records only make a separately authorized baseline-execution prompt eligible.

## 18. One-repair-and-replay and anti-platform boundary

- Baseline execution must use the frozen corpus and oracle before any repair.
- At most one bounded seam repair is allowed after a valid baseline failure.
- The repair may touch only the failing producer/consumer seam required by the ratified responsibility.
- P1 repair cannot be adapter-only; the displayed PCC decision path must consume and enforce the binding.
- A repair requires a new affected-path freeze and ownership preflight.
- Mutation axes, oracle semantics, and claim ceilings remain unchanged.
- One complete 21-case replay is required; selective replay cannot establish pass.
- If the repair requires reclassifying a mutation, weakening a ceiling, adding a fourth adapter, or changing the ground truth, abort and retire the pilot.

Version 1 remains:

- exactly three adapters;
- exactly 21 primary cases;
- no discovery mechanism, fourth path, network mode, UI, API, service, database, scheduler, leaderboard, or automatic refresh;
- no common-model field that merely encodes a consumer-specific predicate.

Retire after the one replay unless at least two independent consumers outside the original three adopt the invariant. Retire any path after two successive revisions requiring semantic adapter rewrites or more than one engineer-day of maintenance per path/revision. Frozen fixtures and results become evidence history, not an operating platform.

## 19. Final adversarial assessment

Strongest duplicate claim: most individual behavior already exists in path-local tests. The pilot’s only defensible novelty is one sealed oracle spanning three independent contracts and the PCC binding seam.

Strongest feasibility risk: P1’s ratified responsibility crosses an information-loss boundary. If a single bounded repair cannot make the displayed PCC decision consume sufficient receipt lineage without rewriting the adapter into the consumer, the baseline remains a valid failure and the path retires after the allowed cycle.

Strongest false-positive risk: an oracle could demand responsibility outside a consumer’s contract. The explicit P1 ratification and P2 exclusion resolve the two known cases; future adjudicators may not widen them.

Strongest false-negative risk: collapsing all degraded states into “not stronger” would hide unchanged `STRONG` or misleading `CONDITIONAL` verdicts. The authority ceiling, strict downgrade, disposition conformance, and raw reason preservation close that hole.

No current source fact makes the three-path common adapter/oracle model logically impossible. The specification is coherent; only evidence-package construction and independent review remain before baseline execution can be considered.

`ADVANCE_TO_IMPLEMENTATION_PROMPT`
