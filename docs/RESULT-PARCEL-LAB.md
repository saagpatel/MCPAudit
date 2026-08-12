# MCP Result Parcel Lab

`mcp-audit result-parcel` is an offline decision laboratory for result
representation, retrieval, retention, and disclosure tradeoffs. It analyzes
synthetic JSON scenarios. It does not run an MCP client or server, fetch a
resource, inspect a credential, allocate the declared payload, or contact an
object store.

## Standards map

Research was refreshed **2026-08-11** against the official MCP
`2026-07-28` specification tag
[`5f5440bb26a62e2cf3440b92da5a667efa03b267`](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/5f5440bb26a62e2cf3440b92da5a667efa03b267)
and the official Tasks extension `main` commit
[`2c1425d9a288b9b1f489430fe1e00bb392b47e48`](https://github.com/modelcontextprotocol/experimental-ext-tasks/tree/2c1425d9a288b9b1f489430fe1e00bb392b47e48).
The extension has no release tag at this as-of point. These are source pins,
not proof that a host implements either surface.

| Surface | What exists in the official source | Classification in this lab |
|---|---|---|
| Tool result | A complete `tools/call` result can carry text, image, audio, `resource_link`, embedded resource, and structured content. Structured content must match `outputSchema` when one is declared. | `inline` is MCP core. |
| Resource link and read | A tool may return a resource link. A client can retrieve resource contents with `resources/read`; one read may return multiple contents. A tool-returned link need not appear in `resources/list`. | `resource_link` is MCP core. Blob retention, deletion, TTL, authorization, and object-store behavior remain explicit scenario evidence. |
| Elicitation / MRTR | In `2026-07-28`, a tool may return `resultType: input_required` with elicitation or other input requests and the client retries with `inputResponses`. | Input acquisition, not a result-delivery mode. It does not justify streaming result bytes. |
| Progress | The `2025-11-25` core utility defined optional `notifications/progress` for an active request. The current Tasks extension does not define progress notifications as result chunks. | `progress_extension` is a provider/local comparison mode for the current profile. It can report status only; payload chunks are not an MCP guarantee. |
| Tasks | Tasks moved from experimental `2025-11-25` core into separately negotiated `io.modelcontextprotocol/tasks`. A server may return `resultType: task`; clients poll `tasks/get`; a completed task contains the final original result. | `tasks_extension`, never MCP core. Host support requires explicit negotiation and remains fixture evidence. |
| Streamed chunks | Current tool result content has no standard result-chunk index, duplicate policy, resume token, or partial-assembly contract. Transport streaming and provider APIs do not create those semantics. | `chunk_stream_extension`; only `provider_extension` or `local_fixture` is accepted by the strict schema. |

Primary sources:

- [MCP 2026-07-28 tool results and stateful-handle guidance](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP 2026-07-28 resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources)
- [MCP 2026-07-28 elicitation / multi round-trip requests](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [MCP 2025-11-25 progress utility](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress)
- [Official 2026-07-28 release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Official Tasks extension specification](https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks)

Normative claims above come from those sources. The 64 KiB inline advisory
bound, suitability rules, risk dimensions, synthetic clocks, and all fault
outcomes are MCPAudit design inferences or local fixture behavior.

## Delivery comparison

| Mode | Best fit | Exposure | Durability | Retry / idempotency | Cleanup |
|---|---|---|---|---|---|
| Inline | Small complete results needed immediately | Whole result crosses the initial result boundary | No later retrieval dependency | One result replacement is comparatively simple | None unless another layer retains it |
| Chunk stream extension | Large incremental provider workflows with a defined sequence contract | Each chunk crosses as delivered | Interruptions and missing chunks need assembly proof | Duplicate indexes and absent idempotency keys are material risks | Provider-specific |
| Progress extension | Status while a separate final result is pending | Status should not contain result bytes | Progress does not retain a final result | Duplicates/decreases are ambiguous; final result remains required | None for status alone |
| Resource link | Large or selectively fetched results | Initial result exposes metadata; later retrieval exposes bytes | Depends on retention, TTL, authority, and blob availability | Retrieval can be retried, but stale or partial bytes need integrity binding | Explicit owner and deletion path required |
| Tasks extension | Negotiated long-running calls needing polling and a durable handle | Task metadata first, final result at completion | Extension TTL and server durability apply | Polling is repeatable; operation idempotency is still application-specific | Task retention is extension/server policy |

No row is universally best. The analyzer reports named reasons and fields; it
does not compute or conceal an aggregate score.

## Scenario and report contracts

The strict identifiers are:

- scenario: `mcpaudit.result-parcel.scenario.v1`;
- report: `mcpaudit.result-parcel.report.v1`;
- current protocol profile: `2026-07-28`;
- Tasks extension identifier: `io.modelcontextprotocol/tasks`.

Every scenario declares payload class, sensitivity, byte size, content type,
synthetic provenance, retention and virtual TTL, integrity metadata, retrieval
authority, redaction stage, delivery semantics, host support, and evidence
provenance. Unknown fields, implicit coercion, duplicate JSON keys, non-finite
numbers, excess depth, oversized keys, and inputs above 2 MiB are rejected.
For confidential resource links, a declaration that authorization is not
required cannot bypass enforced principal binding. Unknown task status,
required-redaction stage, or observed content type produces an `UNKNOWN`
recommendation rather than an invented failure or complete pass.

Emit the authoritative machine-readable schemas:

```sh
uv run mcp-audit result-parcel schema scenario
uv run mcp-audit result-parcel schema report
```

The report is deterministic canonical JSON when `--format json` is selected.
It includes:

- `suitability`: suitable, conditional, unsuitable, or unknown;
- information exposure, durability, retry/idempotency risk, and cleanup burden;
- stable `MCPPARCEL000`–`MCPPARCEL013` findings;
- the exact input field names used by every explanation;
- explicit `unknowns`, assumptions, coverage, and a bounded claim.

## Five-minute demo

```sh
# 1. Discover built-ins.
uv run mcp-audit result-parcel builtins

# 2. Compare a small inline parcel with an 8 MiB inline parcel.
uv run mcp-audit result-parcel analyze --builtin small-inline
uv run mcp-audit result-parcel analyze --builtin large-inline

# 3. Compare the same large size as a retained resource link.
uv run mcp-audit result-parcel analyze --builtin large-resource-link

# 4. Reproduce a supplied failure path in canonical JSON.
uv run mcp-audit result-parcel analyze \
  tests/fixtures/result_parcel/integrity-mismatch.json --format json

# 5. Generate a one-terabyte synthetic metadata scenario without allocating
#    one terabyte, save stdout if desired, then analyze the saved JSON.
uv run mcp-audit result-parcel generate-large \
  --scenario-id one-terabyte-metadata \
  --size-bytes 1099511627776 \
  --mode resource_link
```

`analyze` exits `0` for `pass`, `1` for `fail` or `unknown`, and `2` for CLI or
file-boundary misuse. Human output is the default; JSON is authoritative for
automation.

## Deterministic fault corpus

`tests/fixtures/result_parcel/` covers small and large inline results, ordered
and interrupted streams, progress status and payload conflation, completed
Tasks, expiring references, missing blobs, stale references, authorization
denial, redaction before and after packaging, content-type mismatch, integrity
mismatch, partial retrieval, duplicate chunks, unsupported host capability,
duplicate keys, malformed JSON, unknown fields, and adversarial non-reflection.
All clocks and faults are declared data.

## Threat boundaries and claim ceiling

- The input must be a stable regular non-symlink file. It is read once through
  an identity-checked descriptor and capped at 2 MiB.
- No scenario-controlled title, URI, query string, payload body, or evidence
  title is copied into findings. Reports expose only the scenario ID, stable
  evidence codes, declared enums and sizes, generated explanations, and a
  digest.
- The lab imports no HTTP, MCP connector, OAuth, browser, keychain, credential,
  environment-discovery, model, scheduler, or object-store client.
- Synthetic large payload generation stores only metadata and a deterministic
  digest label. It does not allocate or hash the declared number of bytes.
- A green fixture proves local deterministic rule behavior only. It does not
  prove protocol conformance, host support, extension negotiation, live
  authorization, object durability, credential safety, production adoption,
  interoperability, or human efficacy.

## P01 and P02 seams

P03 owns the representation and retrieval decision after an operation has a
result or result handle:

- **P01 task lifecycle** owns creation, status transitions, cancellation, and
  lifecycle correctness. P03 accepts only the declared terminal task/result
  posture; it does not simulate task state transitions.
- **P02 session and replay faults** owns resume, reconnection, replay, and
  session-fault behavior. P03 evaluates duplicate chunks and idempotency
  declarations at the parcel boundary; it does not infer why a replay occurred
  or implement session recovery.

Future integration should pass versioned P01/P02 evidence into a P03 scenario
adapter. It must not merge their lifecycle state machines into this analyzer.
