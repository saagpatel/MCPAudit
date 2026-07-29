# MCP 2026 Stateless Round-Trip Auditor

`mcp-audit roundtrip` is an offline, fixture-first auditor for observable
invariants in program-owned synthetic MCP `2026-07-28` exchanges. It does not
connect to an MCP server, discover local MCP configuration, execute messages, or
accept production logs.

The implementation follows the final
[MCP `2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28)
and the official
[TypeScript SDK migration guidance](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28).
The final specification makes `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` required on each request.
`io.modelcontextprotocol/clientInfo` is a `SHOULD`, not a requirement, and this
auditor does not fail a request solely because it is absent. Server identity is
also not treated as a discovery security boundary.

## Commands

```bash
mcp-audit roundtrip scan TRACE.json
mcp-audit roundtrip scan TRACE.jsonl --json report.json --sarif report.sarif
mcp-audit roundtrip schema trace
mcp-audit roundtrip schema jsonl-manifest
mcp-audit roundtrip schema request-state-witness
mcp-audit roundtrip schema report
```

`scan` writes canonical JSON to standard output unless `--json` is present.
`--sarif` is an additive SARIF 2.1.0 projection through MCPAudit's existing
SARIF generator. It does not change the default connected scan or
`AuditReport` schema version `1`.

Exit codes are:

- `0`: the accepted trace verdict is `pass`;
- `1`: the verdict is `fail`, `unknown`, or `unsupported`;
- `2`: the input could not be safely read or validated, or an output could not
  be safely committed.

Output paths are no-clobber unless `--force` is explicit. Inputs must be regular,
non-symlink files. Output/input aliases and JSON/SARIF output aliases are
rejected.

## Input contracts

JSON traces use `mcpaudit.mcp-roundtrip.trace.v1`. JSONL traces start with a
`mcpaudit.mcp-roundtrip.trace-jsonl.v1` manifest and then contain one event per
line. Both declare:

- `program_owned: true`;
- a safe synthetic `fixture_id`;
- `protocol_revision: "2026-07-28"`;
- `transport: "streamable-http"` or `"stdio"`;
- optional trusted request-state witnesses;
- strictly increasing event `sequence` values.

Event kinds are `client_request`, `server_response`, `server_request`,
`server_notification`, and `stream_broken`. Message events carry one JSON-RPC
object. Client requests require a synthetic principal alias. HTTP events may
carry bounded headers and a status. `stream_broken` carries the interrupted
request ID; a later client request uses `retry_of` to make retry correlation
observable.

This format is deliberately not a transcript format. Do not translate or paste
real logs into it. Construct minimal synthetic fixtures whose values belong to
the program and contain no credentials or user data.

## Stable rules

| ID | Observable invariant |
|---|---|
| `MCPRT000` | The strict trace schema, revision, and transport are supported. |
| `MCPRT001` | Every request carries protocol version and client capabilities; a mismatched version is explicitly rejected rather than silently accepted. |
| `MCPRT002` | An observed `server/discover` result agrees with later version and server-capability behavior. Absence is not a failure because the client call is optional. |
| `MCPRT003` | Streamable HTTP `MCP-Protocol-Version`, `Mcp-Method`, required `Mcp-Name`, and observable `x-mcp-header`/`Mcp-Param-*` mirrors match the body after defined decoding. The body remains the comparison source. |
| `MCPRT004` | Results use required `resultType`; MRTR is limited to supported methods, input request/response keys and client capabilities correlate, retries preserve method/parameters/state and use a fresh request ID, and no 2026 server request appears. |
| `MCPRT005` | Observable `requestState` use does not cross principal, method, salient-parameter, or witnessed-expiry boundaries. Cryptographic protection is `UNKNOWN` without a matching trusted witness. |
| `MCPRT006` | A broken Streamable HTTP response stream is retried with a new JSON-RPC request ID; duplicate client request IDs are not accepted. |

Rule statuses are `PASS`, `FAIL`, `UNKNOWN`, `UNSUPPORTED`, and
`NOT_APPLICABLE`. Missing correlation evidence is `UNKNOWN`; it is never
converted to pass. A non-applicable surface means the relevant event was not in
scope, such as HTTP headers in a stdio fixture. Unsupported schemas, revisions,
and transports receive a structured `unsupported` verdict and are not
evaluated as clean.

The fixture matrix under `tests/fixtures/roundtrip/` contains vulnerable,
negative, and near-miss controls for every semantic rule. Each vulnerable
control changes the target invariant; negative and near-miss controls prevent
lookalikes from firing. Additional fixtures cover malformed JSON, duplicate
keys, unsupported revisions, credential-looking material, event ordering, and
JSONL input. Tests generate resource-limit and expiry cases without storing
large artifacts.

## Determinism, limits, and redaction

`mcpaudit.mcp-roundtrip.report.v1` is sorted compact JSON with one terminal
newline. It contains no timestamp or input path. The same accepted input bytes
produce the same report bytes.

Limits recorded in every report are:

- 2 MiB per input;
- 40 JSON nesting levels;
- 512 events;
- 50,000 JSON nodes;
- 16 KiB per string;
- 128 KiB per JSONL line.

Duplicate object keys and non-finite JSON constants are rejected. Credential
field names, bearer-like values, API-key-like values, JWT-like values, and
private-key markers are rejected with a generic diagnostic that does not echo
the value. Findings use event sequence numbers, safe method names, and hashes;
they do not include arbitrary message bodies, principal values, request state,
headers, parameters, or absolute paths.

## Claim ceiling

A report supports one narrow claim: the supplied program-owned trace does or
does not satisfy the implemented observable invariants.

It does not prove:

- real-host security, runtime isolation, authentication, authorization, or
  credential correctness;
- request-state cryptography without an explicit matching trusted witness;
- production behavior, live server conformance, or SDK interoperability;
- network, browser, OAuth, keychain, cookie, secret-store, or MCP configuration
  state;
- anything absent from the synthetic trace.

Witnesses are program-owned test evidence, not independent attestations. A
passing report is not permission to generalize the fixture result to a live
host or deployment.
