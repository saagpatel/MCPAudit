# MCP Subscription Stream Integrity Auditor

Status: experimental, fixture-first, offline.

`mcp-audit subscription-stream` evaluates program-owned synthetic traces for
observable routing, opt-in, correlation, and lifecycle invariants in MCP
protocol revision `2026-07-28`. It does not open a network, SSE, or stdio
stream.

## Normative profile

The supported profile is pinned to MCP `2026-07-28`:

- [MCP specification revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [immutable 2026-07-28 TypeScript schema snapshot](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa7306efa4dcc03a2a9f2f223e3b2d7a0c5f3ded/schema/2026-07-28/schema.ts)
- [SEP-2575: Make MCP Stateless](https://modelcontextprotocol.io/seps/2575-stateless-mcp)

The analyzer implements this narrow split:

- A normal MCP request owns its response stream. Request-scoped
  `notifications/progress` and deprecated `notifications/message` messages
  remain on that stream before the final response.
- `subscriptions/listen` opens a separate long-lived notification stream. Its
  filter is opt-in, its first server notification is
  `notifications/subscriptions/acknowledged`, and each notification delivered
  on it carries the original listen request ID as
  `io.modelcontextprotocol/subscriptionId`.
- The graceful close response preserves that subscription ID. Cancellation,
  disconnect, close, and trace-declared replacement terminate the old stream.
  A current-protocol graceful close is a JSON-RPC 2.0 result with
  `resultType`. A later listener is evaluated as a new stream.

This feature intentionally does not evaluate general per-request `_meta`,
headers, MRTR input requests/responses, or retry correctness. Those belong to
the independent stateless round-trip lane.

## Input contract

The strict input identifier is
`mcpaudit.mcp-subscription-trace.v1`. Print its JSON Schema with:

```bash
mcp-audit subscription-stream schema trace
```

The model accepts either one JSON object or JSONL with a header object followed
by one event object per line. The JSONL header contains every top-level field
except `events`; the reducer reconstructs the same strict model before
evaluation. Blank lines, oversized lines, an embedded header `events` field, or
non-object event lines are unknown evidence.

Every trace declares:

- `program_owned: true`;
- a bounded `fixture_id` and one of `vulnerable`, `negative`, or `near_miss`;
- whether the finite observation is complete;
- a bounded observed duration;
- an ordered event list.

Every event explicitly identifies its stream kind (`request` or
`subscription`), stream ID, request ID, subscription ID, direction, lifecycle,
protocol version, offset, and JSON-RPC message. Disconnect events carry no
message. Replacement openings identify the prior stream they replace.
Subscription notifications must have JSON-RPC 2.0 notification shape, and
message/envelope identifiers are compared with type-exact stream identity.

For `notifications/resources/updated`, an exact notification URI can bind
directly to the listener's acknowledged resource subscription. A sub-resource
or otherwise non-exact URI requires
`declared_resource_subscription` in the event. The analyzer checks that
declaration against the listener's acknowledged filter; it does not infer URI
hierarchies or authorization. Resource subscription, update, and declared
binding values must be bounded syntactically valid URIs. Multiple active
listeners may independently acknowledge the same resource.

Unknown fields, duplicate JSON keys, non-standard numeric constants, excessive
nesting, and invalid strict types cannot become passing evidence.

## CLI and output

Scan one trace and write canonical JSON to standard output:

```bash
mcp-audit subscription-stream scan tests/fixtures/subscription_stream/wrong-type-negative.json
```

Project the same canonical findings to SARIF 2.1.0:

```bash
mcp-audit subscription-stream scan TRACE.json --format sarif
```

The command never writes a report file itself. Use caller-owned redirection if
an artifact is needed. Exit codes are:

- `0`: supported trace passed with complete coverage;
- `1`: the report verdict is `fail` or `unknown`;
- `2`: the input path could not be safely read.

Malformed, schema-invalid, truncated, missing-ack, ambiguous, compatibility-era,
or unsupported evidence produces a canonical report with `coverage: unknown`;
it does not silently exit as clean. An observed violation can still produce
`verdict: fail` while coverage remains unknown.

The strict report identifier is
`mcpaudit.mcp-subscription-report.v1`. Print its schema with:

```bash
mcp-audit subscription-stream schema report
```

JSON and SARIF contain the input SHA-256 but no absolute input path. Findings
use hashed stream, identifier, and resource references; JSON-RPC data and raw
resource URIs are not echoed.

## Stable rules

| Rule | Outcome | Observable invariant |
|---|---|---|
| `MCPSUB000` | unknown | Trace coverage is malformed, incomplete, unsupported, or ambiguous |
| `MCPSUB001` | violation | Notification type is present in both the listen request and acknowledgment |
| `MCPSUB002` | violation | Listen request ID is preserved on subscription notifications and graceful close |
| `MCPSUB003` | violation | Request-scoped and subscription-scoped notifications remain on their own streams |
| `MCPSUB004` | violation | Resource update binds to this listener's acknowledged resource subscription |
| `MCPSUB005` | violation | No server message follows close, cancellation, disconnect, or replacement |
| `MCPSUB006` | violation or unknown | Acknowledgment is first, singular, filter-bounded, and observable |
| `MCPSUB007` | unknown | Older protocol-era events are compatibility evidence, not current success |

Findings are reduced immutably in input order and sorted deterministically.
Harmless interleaving across streams does not alter a verdict when each stream's
causal order and identifiers remain intact.

## Bounds

The scanner refuses or reports unknown beyond these limits:

| Surface | Limit |
|---|---:|
| Input bytes | 2 MiB |
| Streams | 64 |
| Events | 2,048 |
| Serialized event bytes | 16 KiB |
| JSON nesting | 16 levels |
| JSON nodes | 131,072 |
| ID length | 128 characters |
| Resource URI length | 2,048 characters |
| Resource subscriptions per filter | 64 |
| Observed duration / event offset | 86,400,000 ms |

Fixture reads use one no-follow regular-file descriptor, enforce size before
and after reading, request nonblocking open semantics, and reject special files
or identity/size changes during the read.

## Semantic controls

`tests/fixtures/subscription_stream/` contains vulnerable, negative, and
near-miss triplets for:

- wrong notification type;
- wrong subscription ID;
- request-scoped leakage;
- wrong resource listener;
- post-close delivery;
- harmless and harmful interleaving;
- disconnect and reconnect;
- older protocol evidence;
- truncated observation;
- missing acknowledgment.

`generate_fixtures.py` regenerates only this program-owned corpus. Focused tests
cover deterministic JSON/SARIF, strict schemas, bounded input, no data echo,
offline execution, and permutation-safe verdicts.

## Claim ceiling

Supported claim: the supplied synthetic streams satisfy or violate the
implemented observable routing and lifecycle invariants.

Not supported:

- delivery reliability or replay;
- authorization effectiveness or resource access control;
- absence of server-side leakage;
- transport encryption or production isolation;
- authentication, host behavior, or live MCP conformance;
- backward compatibility beyond classification of the supplied legacy events.

A passing fixture is not evidence that a server, SDK, transport, or deployment
is safe.
