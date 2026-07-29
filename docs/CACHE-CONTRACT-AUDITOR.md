# MCP Cache Contract Auditor

The MCP Cache Contract Auditor is an **experimental, fixture-first** analyzer
for the observable caching rules introduced by MCP protocol revision
`2026-07-28`. It runs a tiny deterministic state machine over a program-owned
synthetic trace. It is not a client cache, server, proxy, HTTP intermediary, or
performance tool.

The command never connects to an MCP server, opens a transport, reads an MCP
configuration, follows a referenced path, inspects credentials, or uses wall
clock time. It accepts one regular JSON file and emits one canonical JSON
report.

## Command

```bash
mcp-audit cache-contract scan tests/fixtures/cache_contract/refresh-negative.json
mcp-audit cache-contract schema trace
mcp-audit cache-contract schema report
```

Exit codes:

- `0`: supported evidence is complete and no contract contradiction remains;
- `1`: at least one finding fired, or coverage is `unknown`/`incomplete`;
- `2`: the input file could not be safely opened or read.

Malformed JSON and strict-contract validation failures still emit a structured
`unknown` report and exit `1`. File-system failures exit `2`.

## Versioned trace contract

The strict input identifier is:

```text
mcpaudit.cache-contract.trace.v1
```

A trace declares:

- `protocol_version`: the protocol revision under audit;
- `trace_complete`: whether all relevant cache decisions and refresh outcomes
  are represented;
- an explicit logical clock through integer `sequence` and `at_ms` on every
  event;
- a request identity containing `protocol_version`, `principal`,
  `cache_partition`, `method`, and all result-affecting `params`;
- response metadata and body for `response` and `refresh` events;
- the referenced cached response/refresh for `use`, `refresh`, and
  `refresh_error` events;
- a normalized change event, authorization partition, and
  `subscription_validated` state for `notification` events;
- optional `page_group` evidence explicitly linking pages from one list
  request.

`cache_partition` is a synthetic assertion that two events share one complete
MCP authorization context. It is not a token, user name, or credential. The
auditor never tries to derive authorization identity from `principal`, inspect
credential material, or prove that a real cache partitions correctly. A
private reuse across different `cache_partition` values is a contradiction. A
different principal label inside one asserted partition is ambiguous and
therefore `UNKNOWN`.

Example:

```json
{
  "schema_version": "mcpaudit.cache-contract.trace.v1",
  "trace_id": "private-list-refresh",
  "protocol_version": "2026-07-28",
  "trace_complete": true,
  "events": [
    {
      "type": "response",
      "event_id": "r1",
      "sequence": 1,
      "at_ms": 0,
      "request": {
        "protocol_version": "2026-07-28",
        "principal": "synthetic-user-a",
        "cache_partition": "synthetic-auth-context-a",
        "method": "tools/list",
        "params": {}
      },
      "result": {
        "resultType": "complete",
        "ttlMs": 100,
        "cacheScope": "private",
        "tools": []
      }
    },
    {
      "type": "use",
      "event_id": "u1",
      "sequence": 2,
      "at_ms": 50,
      "source_event_id": "r1",
      "request": {
        "protocol_version": "2026-07-28",
        "principal": "synthetic-user-a",
        "cache_partition": "synthetic-auth-context-a",
        "method": "tools/list",
        "params": {}
      }
    }
  ]
}
```

The event array may be serialized in any order. The analyzer uses the explicit
unique `sequence` field, verifies that `at_ms` is nondecreasing in that causal
order, and canonicalizes events before hashing the logical trace. Equal clock
values are unambiguous when `sequence` establishes the order. A clock
regression, duplicate identity, missing source, or non-causal source is
`MCPCACHE000`, never a passing result.

## Supported protocol surface

This version analyzes complete results for:

- `tools/list`;
- `prompts/list`;
- `resources/list`;
- `resources/templates/list`;
- `resources/read`.

MCP `2026-07-28` also makes `server/discover` cacheable. Discovery is
intentionally outside this list/read analyzer and is reported as an explicit
coverage gap rather than silently treated as checked. Earlier and future
protocol versions are unsupported and produce `UNKNOWN`; older results are not
graded for missing `ttlMs`/`cacheScope`.

The implementation is aligned to the final
[MCP caching contract](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching),
[tools contract](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
[prompts contract](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts),
[resources contract](https://modelcontextprotocol.io/specification/2026-07-28/server/resources),
[subscriptions contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions),
[versioning contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
and
[transport model](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).
The versioned
[authoritative JSON Schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/2026-07-28/schema/2026-07-28/schema.json)
defines `ttlMs` as an integer with minimum `0`, `cacheScope` as `public` or
`private`, and requires both on cacheable complete results.

## Protocol rules and simulator policy

The distinction matters:

| Surface | MCP contract | Simulator treatment |
| --- | --- | --- |
| Required metadata | Current complete cacheable results require `resultType`, `ttlMs`, and `cacheScope` | Missing and invalid metadata are separate MUST-level findings |
| Cache key | Method plus every result-affecting parameter must match | Protocol version, method, and canonical parameters are bound; `public` never relaxes this |
| Private scope | A private entry must not cross authorization contexts | `cache_partition` is the trace's explicit authorization-context assertion |
| TTL | Fresh only while `now < received + ttlMs`; re-fetch on stale access is SHOULD | Use at equality or later is a SHOULD-level finding when a complete trace records no failed refresh |
| Failed refresh | A client MAY serve stale after a re-fetch error | A causal, exact-key `refresh_error` makes later stale use permitted; the auditor does not call it a violation |
| Change event | A received relevant notification immediately makes the relevant cached result stale | Only validated normalized subscriptions and exact supported method/URI mappings invalidate |
| Pagination | Pages have independent TTLs; one list request must keep the same cache scope | `page_group` is required before the cross-page MUST can be evaluated |
| Ordering | Unchanged `tools/list` results SHOULD use deterministic ordering | Only unpaginated, same-key, same-set tools results are compared |

MCP does **not** specify URI alias/prefix invalidation, arbitrary dependency
graphs, notification delivery to other cache instances, semantic shareability
across different request keys, or deterministic ordering for prompts,
resources, templates, discovery, or resource contents. The analyzer does not
invent those rules. Unsupported relationships are `UNKNOWN` or remain out of
scope.

Results from requests carrying `inputResponses` or `requestState`, and
`resultType: "input_required"` results, are not cacheable. Storing them fires
`MCPCACHE009`.

## Stable findings

| Rule | Severity | Requirement | Observable contradiction |
| --- | --- | --- | --- |
| `MCPCACHE000` | unknown | unknown/policy bound | Malformed, unsupported, truncated, clock-ambiguous, non-causal, or incomplete evidence |
| `MCPCACHE001` | high | protocol MUST | Required current cache metadata is absent |
| `MCPCACHE002` | high | protocol MUST | TTL or cache scope metadata is invalid |
| `MCPCACHE003` | high | protocol MUST NOT | A private entry crosses asserted authorization partitions |
| `MCPCACHE004` | high | protocol MUST NOT | Reuse or refresh crosses protocol version, method, or result-affecting parameters |
| `MCPCACHE005` | medium | protocol SHOULD | A complete trace uses an entry at/after TTL without a valid refresh or recorded refresh error |
| `MCPCACHE006` | medium | protocol SHOULD | An unchanged unpaginated tools list changes deterministic order |
| `MCPCACHE007` | medium | protocol contract | An entry is used after a relevant validated notification without refresh/error evidence |
| `MCPCACHE008` | high | protocol MUST | Explicitly linked pages from one list request disagree on `cacheScope` |
| `MCPCACHE009` | high | protocol MUST NOT | An input-required or multi-round-trip retry result is cached |

`MCPCACHE005` is deliberately not a MUST-level claim. TTL is a freshness hint,
not a guarantee that server data remains unchanged for that duration, and MCP
permits serving stale data after a failed refresh. The report records the
complete-trace/no-refresh-error assumption that makes the SHOULD-level finding
meaningful.

## Change-event mapping

A `notification` event means the trace has already normalized a notification
received after a valid `subscriptions/listen` acknowledgment. Set
`subscription_validated: false` when that proof is absent; the event becomes
`UNKNOWN` and does not invent invalidation.

The finite mapping is:

- `notifications/tools/list_changed` → `tools/list`;
- `notifications/prompts/list_changed` → `prompts/list`;
- `notifications/resources/list_changed` → `resources/list` and
  `resources/templates/list`;
- `notifications/resources/updated` → `resources/read` with an exact URI
  match.

This mapping follows the current caching contract and the accepted
[SEP-2549 notification mapping](https://modelcontextprotocol.io/seps/2549-TTL-for-list-results#motivation).
It does not treat absence of a notification as a violation.

Private entries are affected only inside their asserted authorization
partition. A retained public entry may be reused across partitions, so a
relevant notification observed in this normalized trace invalidates that
shared entry for every later use. The auditor does not claim that the
notification was delivered to another client or cache instance.

## Bounds and privacy

The analyzer enforces:

- 1 MiB maximum input;
- 2,048 events;
- 512 retained entries;
- 256 KiB per result body;
- 8 KiB per canonical request/notification key;
- 256 characters per JSON object key;
- 32 JSON nesting levels;
- logical times and TTLs within `0..2^53-1`;
- 2,048 report findings.

Inputs must be regular non-symlink files. One descriptor supplies the bounded
bytes, and identity/size/mtime are rechecked after the read. The analyzer never
opens paths named inside the trace.

Reports include a canonical logical-trace SHA-256, event sequence numbers, and
fixed evidence codes. They do not reflect principal names, partition labels,
methods parameters, resource URIs, response bodies, absolute input paths,
credentials, or arbitrary validation error text. The hash proves only report
repeatability for the supplied synthetic bytes; it is not an authenticity or
confidentiality proof.

## Output and determinism

The report contract is:

```text
mcpaudit.cache-contract.report.v1
```

It uses sorted compact UTF-8 JSON with one terminal newline. There is no
timestamp, duration, hostname, platform, random identifier, or absolute path.
Findings are deterministically ordered. The same logical trace produces
byte-identical output across wall-clock values and event-array serialization
orders when explicit causal order is unchanged.

Verdicts:

- `pass`: coverage is complete and no finding or ambiguity remains;
- `fail`: at least one non-unknown rule fired (coverage may also be incomplete);
- `unknown`: no concrete contradiction is proven, but coverage is unsupported,
  malformed, ambiguous, or incomplete.

## Fixture controls

`tests/fixtures/cache_contract/` contains matched vulnerable, negative, and
near-miss triplets for:

- missing metadata and invalid TTL;
- private partitioning and public cross-principal reuse;
- wrong request-key reuse;
- expiry and successful/failed refresh behavior;
- normative and benign change events;
- deterministic ordering drift;
- logical-clock ambiguity;
- truncated evidence.

Additional malformed and unsupported-version fixtures drive the CLI's
fail-closed behavior. Tests cover schema strictness, pagination scope, MRTR
non-cacheability, private-data non-reflection, canonical JSON, no-wall-clock
behavior, and serialization-order independence.

## Claim ceiling

A passing report means only:

> The supplied synthetic trace contains no contradiction covered by the
> implemented observable MCP `2026-07-28` list/read cache contract, under the
> report's explicit assumptions and bounds.

It does **not** prove:

- HTTP cache compliance or header behavior;
- a performance improvement or cache hit rate;
- live MCP server correctness;
- client, proxy, browser, gateway, or intermediary behavior;
- authorization, authentication, access control, or confidentiality;
- that `public` data is safe for any semantically different request;
- notification delivery, subscription validity, or invalidation relationships
  not explicitly represented by the supported trace;
- any property of a production cache, log, transcript, or user.

Keep this capability fixture-only. A real proxy, connected client, production
log ingestion, credential inspection, or general caching library is outside its
contract.
