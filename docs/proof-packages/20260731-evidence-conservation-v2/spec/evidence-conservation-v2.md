# MCPAudit Evidence Conservation v2

Status: `EVIDENCE_PACKAGE_ONLY` candidate. This specification authorizes no
consumer invocation, admission, baseline execution, publication, launch,
deployment, or scheduler operation.

## Contract authority

The normative adjudication is task `019fb993-a5c7-7100-aaa2-a0882d3d0724`,
whose terminal result is `V2_CONTRACT_APPROVED`. The rejected v1 package is
historical evidence only and supplies no fixture schema or admission claim.

## Corpus

The primary corpus is exactly three controls and eighteen one-axis mutations.
P1 and P2 use `(present,current,visible,consistent,supported,bound)`. P3 uses
`(present,current,visible,consistent,supported,private)`. Evidence ordering is
path-local; cross-path coordinate comparisons are invalid.

| Case | Authority ceiling | Disposition | Required reason family |
|---|---|---|---|
| P1-C | STRONG | VALID | `complete` |
| P1-01 | NONAUTHORITATIVE | MISSING | `required_provider_missing` |
| P1-02 | NONAUTHORITATIVE | STALE | `receipt_stale` |
| P1-03 | NONAUTHORITATIVE | MASKED | `required_count_redacted` |
| P1-04 | NONAUTHORITATIVE | CONTRADICTORY | `pagination_incomplete` |
| P1-05 | NONAUTHORITATIVE | UNSUPPORTED | `receipt_schema_unsupported` |
| P1-06 | NONAUTHORITATIVE | MISBOUND | `subject_identity_mismatch` |
| P2-C | STRONG | VALID | `fixture_candidate_valid` |
| P2-01 | NONAUTHORITATIVE | MISSING | `missing-receipt` |
| P2-02 | NONAUTHORITATIVE | STALE | `candidate_expired` |
| P2-03 | NONAUTHORITATIVE | MASKED | `masked` |
| P2-04 | BLOCKED | CONTRADICTORY | `fresh_grade_binding_mismatch` |
| P2-05 | BLOCKED | UNSUPPORTED | `successful_scan_receipt_schema_invalid` |
| P2-06 | BLOCKED | MISBOUND | `receipt_scan_binding_mismatch` |
| P3-C | STRONG | VALID | `verified` |
| P3-01 | NONAUTHORITATIVE | MISSING | `anchor_missing` |
| P3-02 | NONAUTHORITATIVE | STALE | `source_changed_since_anchor` |
| P3-03 | BLOCKED | MASKED | `digest_mismatch` |
| P3-04 | BLOCKED | CONTRADICTORY | `byte_size_mismatch` |
| P3-05 | BLOCKED | UNSUPPORTED | `schema_incompatible` |
| P3-06 | BLOCKED | NOT_PRIVATE | `backup_permissions_not_private` |

P1-06 changes only the snapshot project's `repo_full_name` from reserved
subject alpha to reserved subject beta while the complete raw receipt remains
keyed to alpha. Producer-head behavior is `UNKNOWN`, is not mutated, and is not
claimed.

P2 is limited to `MCPTrustPerServerFixtureAdmissibilityV1`. Each fixture carries
a complete frozen `EngineResult` and a complete `RefreshCandidateV1` artifact
set appropriate to its semantic mutation. Global publication, refresh launch,
deployment, live scanning, and scheduler readiness are excluded.

P3 uses a genuine schema-22 source and the exact two-file `RecoveryAnchorV1`
bundle. P3-06 changes only actual `anchor.sqlite` mode from `0600` to `0644`.
Its raw result is invalid/not-ready with `permissions=not_private`,
`recovery_readback=unverified`, only `backup_permissions_not_private`, and no
`source_current` member. Its ceiling is `(BLOCKED, NOT_PRIVATE)`. The chmod
operation's inode ctime change is an unavoidable excluded materialization
effect, completed before verification and absent from the oracle. Unsupported
or unproved POSIX semantics make the environment `UNKNOWN` and require `ABORT`;
mode behavior is never emulated.

## Boundary corpora

There are exactly six no-op boundaries and six near-miss boundaries. The sixth
P3 near miss adds only `anchor.sqlite-wal` containing fixed bytes `b"untracked"`
to an otherwise exact two-file bundle; the required reason is
`anchor_artifact_set_mismatch`. It is not a primary mutation.

## Adapters and artifact safety

Adapters may only decode, materialize, invoke an entrypoint under future
separate authority, and capture exact raw bytes. They may not compare subject
identities, recompute grades, synthesize fields, classify from fixture labels,
or manufacture reason codes. Consumer-visible bytes contain reserved synthetic
subjects and no case or oracle labels. Secret/privacy validation recursively
decodes base64, tar, and SQLite content.

## Candidate records and transitions

The package contains exactly 29 prerequisite candidate records: one boundary
decision, three freeze receipts, one oracle adjudication, twenty-one fixture
admissibility records, one determinism profile, one coverage delta, and one
ownership preflight. `ADMITTED` is invalid unless prerequisites are satisfied
and at least two independent review receipts exist. All independent-review
fields in this candidate remain pending. Exact pnpm 11.5.2 remains `UNKNOWN`,
so P1 freeze admission is blocked. A second supported deterministic environment
also remains pending.

## Coverage and claim ceiling

Primary coverage is exactly `11 COVERED / 6 PARTIAL / 1 CROSS`; all three
controls have direct coverage. The maximum claim is that this package is ready
for blind independent review. No package result proves consumer behavior,
runtime safety, portfolio correctness, recovery safety, server safety, or pilot
admission.
