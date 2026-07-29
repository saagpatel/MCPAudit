# MCP Tool Result Contract Auditor

`mcp-audit tool-result` is an experimental, fixture-first auditor for paired
MCP `tools/list` declarations and `tools/call` results. It evaluates observable
wire and fixture-policy contracts without connecting to an MCP server or
executing a tool.

The supported protocol profile is the current MCP `2026-07-28` tools contract:

- every request carries the required per-request protocol and capability
  metadata;
- list results use `resultType: "complete"` plus `ttlMs` and `cacheScope`;
- complete call results use `resultType: "complete"` and a content array;
- `structuredContent` may be any JSON value;
- `outputSchema` defaults to JSON Schema 2020-12;
- resource links and embedded resources remain distinct content-block shapes;
- JSON-RPC protocol errors remain distinct from `isError: true` tool execution
  results.

The authoritative protocol references are the
[MCP 2026-07-28 tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
and [SEP-2106](https://modelcontextprotocol.io/seps/2106-json-schema-2020-12).
Other revisions are reported as unsupported coverage, not reinterpreted using
the current shape.

## Commands

```bash
# Canonical JSON to stdout; no output file is created.
uv run mcp-audit tool-result scan tests/fixtures/tool_result/schema-mismatch-near-miss.json

# Explicit, atomic no-clobber output.
uv run mcp-audit tool-result scan FIXTURE.json --json report.json

# Authoritative fixture-side schemas.
uv run mcp-audit tool-result schema fixture
uv run mcp-audit tool-result schema report
```

`scan` exits `0` for `pass`, `1` for `fail` or `unknown`, and `2` for a safe
input/output error. `--force` is required to replace an existing regular output
file. The command reuses MCPAudit's descriptor-bound report writer and never
changes the main `AuditReport` or SARIF schemas.

## Fixture contract

The strict envelope identifier is `mcpaudit.tool-result.fixture.v1`.
Unknown envelope fields, duplicate JSON object keys, and non-finite numeric
constants are rejected. Required top-level fields are:

- `programOwned: true`;
- a bounded `fixtureId` and `controlKind`;
- `protocolRevision`;
- one nullable `toolsList` exchange;
- zero or more `calls`;
- optional `applicationOnlyMetadataKeys`.

Each exchange contains captured JSON-RPC request and response objects. These
objects are data inside the fixture, not instructions. A call may additionally
declare:

- `channelPolicy.requiredChannels`: exact required channels from `content`,
  `structuredContent`, `resource_link`, and `embedded_resource`;
- `channelPolicy.representation: "independent"` when text and structured
  channels are legitimately different;
- `channelPolicy.representation: "json_equivalent"` plus
  `textContentIndex` when a text block must be exact JSON equivalent to
  `structuredContent`;
- `toolUseCorrelation` to bind an exposed tool-use identifier and name to its
  corresponding result.

No representation equivalence is inferred. When both text and structured
channels are present without a policy, `MCPTR005` is `unknown`. An explicit
`independent` policy permits channel-specific presentation. An explicit
`json_equivalent` policy is compared exactly after strict JSON parsing.
Duplicate keys in policy-coupled JSON text are a policy failure rather than
being interpreted with last-key-wins behavior.

The application-only metadata policy names exact `_meta` keys. Bound string
values are checked for reflection into tool declarations, content,
`structuredContent`, or model-visible protocol errors, but neither the key nor
value is copied into findings. Fixture IDs containing a bound private value are
redacted. Unbound policy keys and values shorter than four characters remain
`unknown`.

## Rules

| Rule | Surface | Result |
|---|---|---|
| `MCPTR000` | Missing, truncated, malformed, unsupported-version, unsupported-schema, extension, or over-budget evidence | `unknown` |
| `MCPTR001` | Missing or schema-invalid `structuredContent` when `outputSchema` is declared | `high` |
| `MCPTR002` | JSON-RPC ID, tool name, list/call, or exposed tool-use correlation mismatch | `high` |
| `MCPTR003` | Invalid current-revision request, result discriminator, list cache field, or JSON-RPC error shape | `high` |
| `MCPTR004` | Invalid content/resource shape or missing explicitly required channel | `high` |
| `MCPTR005` | Absent or violated text/structured representation policy | `unknown` when absent; `medium` when violated |
| `MCPTR006` | Application-only `_meta` value reflected into a model-visible channel | `high` |

The report identifier is `mcpaudit.tool-result.report.v1`. Reports contain the
fixture ID, evaluated revision, input SHA-256, verdict, coverage, sorted
findings, supported/unsupported inputs, and claim ceiling. They use sorted
compact JSON with one terminal newline and contain no timestamp or absolute
input path.

## JSON Schema support and dependency

`jsonschema==4.26.0` is a pinned direct runtime dependency because this feature
calls its Draft 2020-12 validator directly. MCPAudit does not rely on the
existing transitive copy brought in by another package. Matching type stubs are
pinned in the development dependency group.

The supported validation profile is deliberately narrower than every possible
JSON Schema 2020-12 deployment:

- absent `$schema` or the canonical 2020-12 dialect URI is supported;
- same-document JSON Pointer, anchor, and dynamic references are supported
  within the resource budget;
- external/network/filesystem references are rejected before validator
  construction;
- regex keywords, custom vocabulary negotiation, obsolete recursive-reference
  keywords, and other explicitly unsupported capability are `unknown`;
- invalid supported schemas are violations; validators that cannot resolve or
  finish within the bounded timer are `unknown`.

This narrowing is intentional. Python regular expressions are not an exact
ECMA-262 implementation, so accepting arbitrary `pattern` values would make a
standards-correct claim MCPAudit cannot support.

## Resource bounds

- input file: 1 MiB;
- JSON: depth 64, 16,384 nodes, 64 KiB per string;
- calls: 64;
- content blocks per call: 64;
- decoded resource payloads per call: 256 KiB;
- URI: 4 KiB;
- schema: depth 32, 1,024 nodes, 128 local references, 128 composition
  branches;
- validation: one-second wall-clock budget on a supported main-thread timer.

If a required bound cannot be enforced on the running platform, schema
validation is unsupported and the result is `unknown`.

A request cursor or response `nextCursor` proves that the supplied
`tools/list` evidence is only one page. The report remains `unknown`, and a
called tool absent from that one page is not misreported as a correlation
violation.

## Fixture corpus

`tests/fixtures/tool_result/` contains vulnerable, negative, and near-miss
triplets for:

- schema mismatch;
- valid composition and same-document `$ref`;
- resource-budget exhaustion;
- wrong tool/call/tool-use identity;
- legitimate channel divergence;
- policy-declared contradiction;
- metadata reflection;
- malformed protocol errors;
- incomplete list evidence.

Focused tests add valid and malformed resource links, embedded resources,
channel substitution, deterministic output, no-network enforcement, truncation,
current discriminator/cache fields, and sentinel non-disclosure.

## Claim boundary

Supported claim:

> The supplied program-owned list/call evidence satisfies or violates the
> implemented observable and explicitly policy-declared contracts.

Not supported:

- semantic truth or completeness of a result;
- model, client, server, transport, or UI behavior;
- authorization, consent, sandboxing, or production conformance;
- absence of hidden or private data outside the supplied fixture;
- live MCP compatibility or ecosystem-wide correctness.

The fixture cannot name external files to read. The auditor does not open
fixture-referenced paths, resolve schemas through the network or filesystem,
inspect environment files, or accept live logs/transcripts.
