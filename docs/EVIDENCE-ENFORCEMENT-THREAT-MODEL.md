# Evidence-to-Enforcement Fixture Threat Model

## Scope and assets

This threat model covers only the experimental, fixture-only AGT adapter. The
protected assets are approval authority, origin-qualified server/tool/schema
identity, deterministic evidence and state digests, program-owned fixture state,
rollback snapshots, and the negative-control handler canaries.

Normal MCP client configuration, real MCP servers, user data, secrets,
credentials, accounts, and external services are out of scope and must remain
untouched.

## Security invariants

- Evidence, recommendation, approval, and effective state are separate strict
  contracts with unknown fields forbidden.
- Only a human-invoked approval command creates `ApprovedPolicyIntentV1`.
- Approval binds the exact recommendation and evidence digests, subject, target
  adapter/runtime, pre-state, approval/expiry times, operator label, and rollback
  identity.
- The compiler either preserves an exact supported decision or fails; it never
  silently weakens constraints.
- Effective enforcement requires readback and behavioral negative controls.
- Only owned, non-symlink fixture-state directories with the reserved basename
  prefix are writable.
- Secret material is never accepted; secret references use an uppercase
  environment-key grammar and validation errors do not echo rejected values.

## Threats and controls

### Identity substitution and approval replay

Changing the source digest, launch digest (including arguments), tool set, tool
schema hash, evidence digest, subject, runtime version, pre-state, expiry, or
rollback identity changes a bound digest or field. Application fails before any
state write. Identical reapplication is the sole pre-state exception: it is
recognized only when current state exactly equals the already-approved intended
state, and it performs no write. Rollback records the exact approval digest in a
revocation ledger before restoring state, so the approval cannot be replayed
after rollback. A no-op also requires the existing rollback record to bind that
exact approval, rollback identity, applied-state digest, and captured pre-state;
identical unowned or differently approved state is rejected.

### TOCTOU and drift

Application and rollback acquire a persistent, program-owned `fcntl` lock for
the fixture directory. Application rereads the current state under that lock,
revalidates the approval binding against the reread digest, and performs a final
pre-state comparison immediately before the rollback/state write sequence. A
different state blocks apply. The trusted process clock rejects future-dated,
older-than-15-minute, or explicitly stale evidence and rejects future or
expired approvals. State writes use exclusive, no-follow, same-directory
temporary files, `fsync`, and `os.replace`. Managed targets, temporary files,
the ownership marker, lock file, and the state-directory leaf may not be
symlinks. The rollback snapshot is written before the new state; interruption
before the state replace leaves the old state active. Rollback rereads under the
same lock and requires the current state to match the snapshot's recorded
applied-state digest.

### Unsupported translation

AGT `MCPGateway` 4.1.0 does not express the requested argument, egress,
filesystem/resource, or secret-reference constraints. Non-empty constraints
therefore return structured `unsupported_translation` errors and cannot apply.

### Runtime failure and false readback

The installed distribution must be exactly
`agent-governance-toolkit-core==4.1.0`. The adapter uses documented public
interfaces only. A sensitive-tool approval callback exception is probed and must
deny. `GatewayConfig` list readback is normalized and compared with the compiled
intent, then positive and negative tool calls prove handler execution or
non-execution. After persistence the adapter rereads and re-probes the stored
state; the receipt uses that readback digest rather than the intended object.
The program-owned counter changes only inside the selected toy handler.
Configuration construction or an interception decision alone is never called
enforcement.

### Partial apply and rollback confusion

Program-owned state uses `state.json`, `rollback.json`, an ownership marker, a
persistent lock file, and `revoked-approvals.json`. The rollback record contains
its identity, exact prior state/digest, applied state digest, and approval
digest. Rollback probes the prior state before mutation, verifies all bindings,
revokes the approval, then verifies the restored digest and behavior. A
post-write failure compensates back to the applied state. A failed later apply
also restores the previous rollback record instead of destroying that lineage.
A replay after rollback fails because the approval is revoked.

### Secret exposure

Models permit only uppercase environment-style secret key names and reject
token-shaped strings, whitespace, or `=` forms that could embed values. The
fixture contains no secret references. CLI input-validation diagnostics are
generic and unexpected failures are fail-closed; rejected values, environments,
and credential stores are never serialized.

## Residual limits

- This proves one local compatibility slice, not production gateway readiness.
- It does not prove AGT versions other than 4.1.0.
- It does not enforce arguments, network, filesystem, resources, or secrets.
- Cooperative fixture commands are serialized per state directory. This is not
  a distributed lock and cannot constrain an unrelated process that ignores the
  program-owned lock contract.
- Crash recovery is limited to ordered atomic replacement and verified
  compensation; there is no transaction journal.
- It does not connect to or execute a configured MCP server.
