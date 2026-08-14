# Delivery Evidence Contract

`mcpaudit.delivery-evidence.v1` is a bounded repository-maintainer contract for proving what exact
MCPAudit bytes were integrated and what the supplied receipts can support. It is not an MCP product
command, live GitHub inspector, release gate, generic evidence framework, or substitute for CI,
runtime, publication, deployment, adoption, or human proof.

Validate a receipt without network access or an LLM:

```bash
python scripts/validate_delivery_evidence.py receipt.json
```

The validator emits canonical JSON. Exit `0` is `PASS`, exit `1` is a validated `FAIL`, exit `3` is
`UNKNOWN`, and exit `2` means the input was unsafe or structurally invalid. Input is limited to a
1 MiB regular non-symlink JSON file. The validator verifies the pre-open and opened identity and
rejects size or modification-time changes during the bounded read; no-follow and non-blocking flags
are added where the host exposes them. Duplicate keys, non-UTF-8 data, unexpected fields, unsafe
file types, and malformed bindings fail closed. Values in the receipt are data only: the validator
does not interpret file paths, execute commands, read credentials, or contact GitHub.

## Evidence classes and boundaries

Immutable integration evidence consists of the exact 40-character revision, protected-main
reachability, merged pull-request identity and integration revision, review status and unresolved
thread count, exact-source security status, and exact-SHA CI receipts. Source and environment use
`sha256:`-prefixed lowercase digests.

A branch is always `mutable_convenience`. Its name, remote-tracking ref, and repository UI linkage
may move or disappear. `absent` does not invalidate correctly bound immutable integration evidence;
`unknown` stays unknown. `present` is valid only when a fresh live observation resolves to the exact
target revision.

Proof boundaries are independent: `source`, `local`, `ci`, `runtime`, `publication`, `deployment`,
`adoption`, and `human_acceptance`. A passing lower boundary is not evidence for a higher one. Each
claim records its own status, supporting boundaries, whether it describes current state, and an
observation time when applicable. `claim_ceiling.proven_boundaries` must exactly match the ordered
set of passing claims and `unproven_boundaries` must contain every other boundary. Its bounded
`statement` is descriptive and cannot raise the mechanically checked ceiling.

Historical receipt production (`producer.produced_at`) is separate from the caller-supplied
`freshness.as_of`. Current branch and current-state claim observations must fall within
`current_state_max_age_seconds`; historical observations may be older but never later than `as_of`.
Timestamps use the full RFC 3339 UTC date-time form with `T`, optional fractional seconds, and `Z`.
The validator never consults wall-clock time.

When `environment_required` is false, environment bindings may be absent. If a target and CI
environment digest are both supplied, they must still match exactly; optionality never admits a
different environment.

## Retention policy

`retention.required: false` means branch preservation is not part of delivery. Policy details are
then null and `exception_path` is `none`.

If retention is required, the receipt must name why the branch is required, its consumer, lifecycle,
mutation authority, deletion policy, and one exception path. With `delete_branch_on_merge: true`,
unconditional durable retention is contradictory. The admitted exception paths are a bounded
repository-setting exception or a bounded post-merge restoration. Either describes authority and
lifecycle; it does not prove current completion. Completion still needs fresh exact-ref readback.

## Deterministic findings

| Code | Meaning |
|---|---|
| `MCPDELIVERY001` | A live branch resolves to the wrong revision. |
| `MCPDELIVERY002` | An immutable or CI receipt revision differs from the target. |
| `MCPDELIVERY003` | The security receipt source digest differs from the target. |
| `MCPDELIVERY004` | Protected-main reachability failed or is unknown. |
| `MCPDELIVERY005` | Review status failed, is unknown, or has unresolved threads. |
| `MCPDELIVERY006` | Security status failed or is unknown. |
| `MCPDELIVERY007` | An exact-SHA CI status failed or is unknown. |
| `MCPDELIVERY008` | A required exact environment binding is unavailable. |
| `MCPDELIVERY009` | A current-state observation is stale or future-dated. |
| `MCPDELIVERY010` | Required retention contradicts automatic deletion. |
| `MCPDELIVERY011` | Required retention lacks fresh exact live-ref completion evidence. |
| `MCPDELIVERY012` | A higher proof boundary is inferred only from source, local, or CI evidence. |
| `MCPDELIVERY013` | The stated claim ceiling differs from the mechanically derived boundaries. |

`FAIL` outranks `UNKNOWN`; `UNKNOWN` outranks `PASS`. Findings are sorted by code, severity, and
message. Equivalent JSON objects therefore produce byte-identical output and the same canonical
input digest.

## Claim ceiling and invalidation

The validator proves only consistency of the supplied bounded receipt. It does not discover whether
the producer is trustworthy or whether GitHub observations are true. Re-read live authority before
making a current claim. Changed revision, source digest, required environment, stale observation,
unresolved review, failed or unknown receipt, ref mismatch, repository-policy contradiction, or
unsupported proof-boundary inference invalidates the affected claim. Unsupported facts remain
`UNKNOWN`; they are never converted into green badges.

Do not place raw secrets, tokens, credentials, complete tool output, private keys, or unbounded prompt
content in a delivery receipt.
