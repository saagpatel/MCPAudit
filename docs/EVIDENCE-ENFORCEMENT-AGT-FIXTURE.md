# Experimental AGT Fixture Enforcement

This is one deliberately narrow evidence-to-enforcement compatibility slice. It
converts a synthetic connected `AuditReport` schema version `1` into a policy
recommendation, requires a separate operator approval, compiles only exact tool
allow/deny/approval decisions, and exercises Microsoft Agent Governance
Toolkit's published `MCPGateway`.

It is **experimental, fixture-only, and pinned to
`agent-governance-toolkit-core==4.1.0`**. It does not build a gateway, launch an
MCP server, inspect normal MCP configuration, or alter any client configuration.
The supported state directory basename must start with
`mcpaudit-enforcement-fixture-`. On first write it must be empty; MCPAudit adds
an ownership marker and thereafter rejects missing/invalid markers, symlinked
directories, and symlinked managed or temporary files. Apply and rollback
serialize mutations with a persistent program-owned lock file in that directory.

## Compatibility target

The adapter imports only the published public interfaces:

- `agent_os.integrations.base.GovernancePolicy`
- `agent_os.mcp_gateway.MCPGateway`
- `agent_os.mcp_gateway.GatewayConfig`
- `agent_os.mcp_gateway.ApprovalStatus`

Startup operations read the installed distribution version and fail closed
unless it is exactly `4.1.0`. The dependency and lockfile are exact-pinned. A
different AGT version requires a new adapter version, compatibility probe,
security review, fixtures, and explicit target-policy update; it must not be
accepted by relaxing the pin.

## Trust boundary

The four contracts remain distinct:

1. `ObservedEvidenceV1` records connected evidence and unknown/degraded states.
2. `PolicyRecommendationV1` is non-authoritative advice derived from that
   evidence.
3. `ApprovedPolicyIntentV1` records an operator's exact approval binding.
4. `EffectiveStateV1` records normalized runtime readback plus behavioral proof.

Risk scores, grades, descriptions, annotations, and model output never become
authorization. Config-only, disconnected, stale, warning-bearing, drifted,
missing, masked, unverifiable, or unknown evidence cannot recommend an allow.
Connected evidence is still stale when it is future-dated or more than 15
minutes old. Apply recomputes freshness from the process UTC clock; neither the
API nor CLI accepts a caller-selected application time.

## Supported translation

Adapter v1 supports only origin-qualified exact tool decisions:

| Fixture tool | Decision | AGT state |
|---|---|---|
| `read_fixture` | allow | allow list |
| `write_fixture` | approval | allow list plus sensitive-tool list |
| `delete_fixture` | deny | deny list |

Default deny is proven by an unknown-tool probe. Any non-empty argument,
network/egress, filesystem/resource, or secret-reference restriction produces a
structured `unsupported_translation` result. The adapter never drops or weakens
an unsupported constraint.

## Operator workflow

Every subcommand emits exactly one JSON object on stdout. Diagnostics go to
stderr. Exit `0` means verified success or verified no-op, `1` means a
fail-closed policy/runtime outcome, and `2` means invalid input.

Prepare evidence, recommendation, and a deterministic no-write diff:

```sh
mcp-audit enforcement-fixture prepare \
  --audit-report examples/enforcement-fixture/synthetic-audit-report.json \
  --origin fixture://mcpaudit/evidence-enforcement \
  --server-name synthetic-policy-server \
  --source-sha256 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --provenance synthetic-connected-audit-report-v1 \
  --created-at 2026-07-20T12:00:00Z \
  --expires-at 2026-07-20T14:00:00Z \
  --rollback-id rollback-fixture-001 \
  --state-dir /tmp/mcpaudit-enforcement-fixture-demo
```

The checked-in report is a schema/behavior fixture, not durable current
evidence. Refresh its synthetic scan timestamp and the command timestamps
together when exercising the example; stale or future-dated input is expected
to block.

Save the nested `evidence` and `recommendation` objects as canonical JSON files.
Approval is an explicit, separate operator action:

```sh
mcp-audit enforcement-fixture approve \
  --recommendation recommendation.json \
  --approved-at 2026-07-20T12:01:00Z \
  --expires-at 2026-07-20T13:00:00Z \
  --operator-label local-fixture-operator
```

Save the emitted `approval` object, then apply:

```sh
mcp-audit enforcement-fixture apply \
  --evidence evidence.json \
  --recommendation recommendation.json \
  --approval approval.json \
  --state-dir /tmp/mcpaudit-enforcement-fixture-demo
```

Identical reapplication returns `no_op` with the same effective-state digest.
It is accepted only when `rollback.json` proves that this exact approval and
rollback identity created the current state; merely pre-seeding identical bytes
does not qualify. `EffectiveStateV1.applied_at` is the approval-bound timestamp,
while freshness and expiry are checked separately against the trusted process
clock, so a later verified no-op retains the same digest.
Rollback requires the exact subject and captured rollback identity. A
successful rollback revokes the approval digest, so the same approval cannot be
used to apply again:

```sh
mcp-audit enforcement-fixture rollback \
  --origin fixture://mcpaudit/evidence-enforcement \
  --server-name synthetic-policy-server \
  --rollback-id rollback-fixture-001 \
  --state-dir /tmp/mcpaudit-enforcement-fixture-demo \
  --rolled-back-at 2026-07-20T12:03:00Z
```

## What enforcement proof means here

Construction and rendered policy are insufficient. A successful apply requires:

- normalized `GatewayConfig` matches the approved supported subset;
- the exact installed runtime version is read back;
- `read_fixture` reaches its handler exactly once;
- `write_fixture` remains blocked/pending without a per-call approval callback;
- `delete_fixture` and an unknown tool remain denied with zero handler calls;
- an approval callback exception fails closed;
- audit decisions are captured; and
- the resulting `EffectiveStateV1` has a deterministic digest.

Application writes only after binding validation, rereads the persisted state,
then rechecks the approval and pre-state under the fixture lock immediately
before writing. It rereads the persisted state, compares its digest, and probes
the reread state once. The toy handler canary is incremented inside the handler
itself, never by the interceptor. A mismatch or post-write failure restores and
verifies both the prior state and prior rollback lineage. Rollback rereads and
validates under the same lock, probes the captured prior state before writing,
and compensates back to the applied state if post-write verification fails.

Model-validation diagnostics are deliberately redacted at the CLI boundary:
malformed input returns a generic error and never echoes the rejected value.
Unexpected exceptions also collapse to one fail-closed JSON object.

See [the threat model](EVIDENCE-ENFORCEMENT-THREAT-MODEL.md) before extending
this adapter.
