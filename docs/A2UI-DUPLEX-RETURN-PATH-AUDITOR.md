# A2UI Duplex Return-Path Auditor

The A2UI Duplex Return-Path Auditor is an **experimental, fixture-first,
offline analyzer** for paired A2UI server-to-client surface messages and
client-to-server action, error, capability, and data-model return evidence. It
answers a narrow question: do the supplied envelopes satisfy the implemented
observable return-path invariants?

This is a different surface from the Agent UI Contract Auditor added in
PR #191. The metadata auditor statically compares declared UI authority,
approval, provenance, evidence, and external destinations. The duplex auditor
indexes a supplied message transcript and checks whether actual synthetic
returns refer back to the active surface/component revision and its emitted
action. It does not rename, extend, or reinterpret `MCPUI001`–`MCPUI006`.

## Command

```bash
mcp-audit agent-ui duplex scan \
  tests/fixtures/a2ui_duplex/mcpdup001-origin-negative.json

mcp-audit agent-ui duplex scan fixture.json \
  --json duplex-report.json \
  --sarif duplex-report.sarif \
  --redact

mcp-audit agent-ui duplex schema fixture
mcp-audit agent-ui duplex schema disclosure-policy
mcp-audit agent-ui duplex schema report
```

The command exits `0` for `pass`, `1` for `fail` or `unknown`, and `2` when an
input or output artifact cannot be safely processed. Without `--json`, the
canonical report is written to stdout. Existing output files are not replaced
unless `--force` is explicit.

## Official A2UI boundary

The implementation follows the common observable return path in the current
[A2UI v0.9 production family](https://a2ui.org/specification/v0.9-a2ui/) and
the [v1.0 candidate schemas](https://github.com/a2ui-project/a2ui/tree/main/specification/v1_0):

- an action carries `name`, `surfaceId`, `sourceComponentId`, `timestamp`, and
  resolved `context`;
- a client error carries a code, message, and surface correlation;
- `a2uiClientCapabilities` declares supported catalog identifiers;
- `a2uiClientDataModel` returns surface-scoped full models when
  `sendDataModel` is active;
- v1.0 may add `wantResponse` and `actionId`.

The renderer guide currently identifies v0.9.1 as production and v1.0 as a
candidate. The auditor therefore supports only the common
`createSurface`/`updateComponents`/`updateDataModel`/`deleteSurface` lifecycle
plus action and error returns. v1.0 function calls, function responses, and
action RPC responses are explicitly unsupported.

A2UI does not define the MCPAudit fixture's transcript sequence, revision
origin, error correlation, acknowledgement, action schema, producer profile,
or disclosure policy fields. Those are program-owned sidecars that make paired
evidence analyzable without claiming a transport binding.

## Paired fixture contract

`mcpaudit.a2ui-duplex.fixture.v1` is one strict JSON object with:

- `program_owned: true`;
- protocol version `v0.9` or `v1.0`;
- producer profile `web-core-react` or `flutter-a2ui`;
- clock domain `fixture-single-clock-v1`;
- a transcript of uniquely sequenced server/client envelopes;
- optional bounded action context/payload schemas;
- an optional versioned full-model disclosure policy.

The input array may be out of order. `sequence` is authoritative, which keeps
benign capture ordering and multi-surface concurrency from becoming findings.
Each server message advances only its surface revision. A component revision
advances only when that component ID appears in an update. An action's
fixture-owned `origin` records the expected surface revision, component
revision, and emitting server message ID; the analyzer recomputes all three.
Delete/recreate starts a new internal surface generation, so an error cannot
correlate through a reused v0.9 surface/component identifier to a message from
the old generation. Action envelopes may carry only the action-origin sidecar,
and error envelopes may carry only the error-correlation sidecar. Malformed
component identifiers make dependent component checks `UNKNOWN` rather than
creating a partial index.

Client metadata preserves the official keys:

```json
{
  "a2uiClientCapabilities": {
    "v0.9": {
      "supportedCatalogIds": ["urn:a2ui:basic:v0.9"]
    }
  },
  "a2uiClientDataModel": {
    "version": "v0.9",
    "surfaces": {
      "checkout": {"quantity": 2}
    }
  }
}
```

The analyzer never fetches a catalog or validates component implementation.
It only compares the active surface's supplied `catalogId` with return-time
capability metadata.

## Stable rules

| Rule | Severity | Observable contradiction |
| --- | --- | --- |
| `MCPDUP000` | unknown | Required evidence is missing/malformed, or the supplied construct is unsupported |
| `MCPDUP001` | high | Returned surface/component/revision/emitting-message origin does not resolve |
| `MCPDUP002` | high | Returned action is undeclared, has different context keys, or fails an explicit bounded schema |
| `MCPDUP003` | medium | Return ID/action ID is duplicated or replayed, or sequence/revision/single-clock evidence is causally impossible |
| `MCPDUP004` | medium | Return-time client capabilities omit the active surface catalog |
| `MCPDUP005` | medium | Renderer error correlation is false or no later server acknowledgement exists |
| `MCPDUP006` | high | Full data-model return lacks `sendDataModel` authority or violates the explicit disclosure policy |

`MCPDUP003` never hashes payload equality or uses timestamps as identity.
Repeated actions are legitimate when observable return/action IDs are distinct
and their origins resolve. Timestamps fire only when the declared single-clock
fixture makes an action earlier than the active surface revision or later than
the observed return, or when a surface's server observations move backward.
Timestamp strings must also represent real UTC calendar instants.

## Action schemas

An action must first be declared by the exact source component's
`action.event.name`. The returned context keys must match that component
declaration. Optional program-owned `context_schema` and `payload_schema`
contracts use a bounded local subset of JSON Schema:

- `type`, `properties`, `required`, `additionalProperties`, and `items`;
- `enum` and `const`;
- string, numeric, and array size bounds.

The complete schema definition tree is validated before any returned value is
evaluated, including schemas for optional properties absent from that return.
Definition traversal and value evaluation have separate 512-visit budgets and
the same 16-level depth limit. `enum` and `const` use JSON value equality:
booleans are distinct from numbers, while numerically equal JSON numbers remain
equal.

References, composition, conditionals, regex patterns, remote schemas, and
executable validators are unsupported and produce `MCPDUP000`, never `pass`.

## Full-model disclosure policy

`a2uiClientDataModel` is evaluated only when the fixture supplies
`mcpaudit.a2ui-duplex.disclosure-policy.v1`. A returned surface must:

1. be active;
2. have been created with `sendDataModel: true`;
3. have an explicit policy rule allowing full-model return; and
4. contain only allowed top-level keys when the policy provides an allowlist.

Omitting `allowed_top_level_keys` from an explicitly allowing rule means that
the program-owned policy places no top-level-key restriction. Supplying
`allowed_top_level_keys: []` is different: only an empty returned model is
allowed.

No returned model plus no policy is a clean non-applicable case. A returned
model plus no policy is `UNKNOWN`. An explicit deny or out-of-policy return is
`MCPDUP006`. The scanner does not invent a disclosure preference from field
names or payload content.

## Errors and acknowledgement

The official error payload is paired with a fixture-owned correlation naming
the source component and earlier server message. The component must be active
on the error's surface and must appear in the correlated server component
update from the same surface generation. A later server envelope must
explicitly acknowledge the client error message ID. This proves only that the
paired transcript contains a correlation and receipt; it does not prove server
logging, remediation, user visibility, or delivery outside the fixture.

## Limits, privacy, and redaction

The auditor accepts only regular, non-symlink JSON files. Existing Agent UI
descriptor-bound reading and atomic report-write controls are reused. It
enforces:

- 1 MiB input size;
- 512 transcript envelopes;
- 2,048 cumulative component definitions;
- 20,000 generic JSON nodes;
- 16 KiB per string;
- 64 JSON nesting levels;
- 16 schema levels, 512 schema-definition nodes, and 512 value-evaluation
  visits per schema.

Credential-looking field names and values, plus private filesystem path-looking
values outside JSON Pointer fields, are rejected before analysis.
Payload values, full model values, disallowed model key names, and error
messages never enter JSON or SARIF findings. `--redact` additionally replaces
fixture, producer, and finding target identifiers with deterministic hashes.

No `.env`, keychain, OAuth store, browser profile, cookie, log, credential
configuration, renderer, network service, or process is accessed.

## Fixtures and semantic proof

`tests/fixtures/a2ui_duplex/` contains negative, vulnerable, and near-miss
triplets for all six rules, plus focused controls for:

- wrong surface and removed component;
- undeclared action and payload mismatch;
- replayed action ID and impossible timestamp;
- mismatched error correlation;
- capability/catalog mismatch;
- allowed, disallowed, and missing-policy model returns.

The corpus covers both producer profiles and both supported protocol families.
Multi-surface, repeated-action, and out-of-order capture near-misses remain
clean.

## Claim ceiling and recommendation

A passing report means only that the supplied paired envelopes contain no
implemented observable contradiction and no unresolved evidence gap. It does
not prove JavaScript/HTML safety, visual correctness, accessibility, host
consent, agent authorization, renderer integrity, AG-UI conformance, transport
interoperability, exploitation resistance, or any real workflow.

**Recommendation: ADOPT as an experimental fixture-only MCPAudit analyzer.**
Six independent return-path rules are represented across two plausible
producer profiles without collapsing into PR #191's metadata rules. Keep it
experimental until independently produced public-safe fixtures demonstrate
usefulness beyond the program-owned corpus.
