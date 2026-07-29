# AG-UI Interrupt/Resume Integrity Auditor

The AG-UI Interrupt/Resume Integrity Auditor is an **experimental,
fixture-first MCPAudit capability**. It reconstructs the observable interrupt
state machine in a program-owned synthetic event/resume transcript. It does not
run an agent, workflow, browser, tool, framework, or transport.

## Pinned upstream contract

The supported profile is pinned to:

- `@ag-ui/core@0.0.57`;
- upstream `ag-ui-protocol/ag-ui` commit
  `34c3e0ceda257dd1366c6bdfe01c52777611e4bf`; and
- the interrupt draft documented in
  [`docs/concepts/interrupts.mdx`](https://github.com/ag-ui-protocol/ag-ui/blob/34c3e0ceda257dd1366c6bdfe01c52777611e4bf/docs/concepts/interrupts.mdx).

The evaluated contract identifier is:

```text
@ag-ui/core@0.0.57+interrupt-draft@34c3e0ceda257dd1366c6bdfe01c52777611e4bf
```

This is a draft upstream surface, not an AG-UI 1.0 stability claim. A different
version or revision is unsupported and produces `UNKNOWN` until its semantic
diff is reviewed.

The primary specification differs from an easy but incorrect “same run”
interpretation: a resume starts a **new run on the same thread**. The
`resume[].interruptId` values bind that new run to the interrupted run’s exact
open set. `parentRunId` remains orthogonal because AG-UI reserves it for
branching and time travel. MCPAudit therefore does not require `parentRunId` to
equal the interrupted `runId`.

## Command

```bash
mcp-audit ag-ui-interrupt scan \
  tests/fixtures/agui_interrupt/agui001-binding-vulnerable.jsonl

mcp-audit ag-ui-interrupt scan transcript.jsonl \
  --json interrupt-report.json \
  --sarif interrupt-report.sarif

mcp-audit ag-ui-interrupt schema fixture-manifest
mcp-audit ag-ui-interrupt schema run-input
mcp-audit ag-ui-interrupt schema event-record
mcp-audit ag-ui-interrupt schema report
```

Exit codes:

- `0`: the supported complete transcript passes every implemented invariant;
- `1`: one or more violations fired, or coverage remains `UNKNOWN`;
- `2`: the input/output artifact is unsafe or cannot be safely read or written.

JSON written to standard output or `--json` is compact, sorted, UTF-8 canonical
JSON with one terminal newline. `--sarif` emits a deterministic SARIF 2.1.0
projection. Existing report files are not replaced unless `--force` is
explicit. Output writes reuse MCPAudit’s descriptor-bound, atomic no-clobber
artifact contract.

## Versioned JSONL input

Line 1 is a program-owned manifest envelope:

```json
{
  "fixture": {
    "schema_version": "mcpaudit.ag-ui-interrupt.fixture.v1",
    "program_owned": true,
    "fixture_id": "parallel-resume-positive",
    "control_kind": "near-miss",
    "protocol": "ag-ui",
    "protocol_version": "@ag-ui/core@0.0.57",
    "contract_revision": "34c3e0ceda257dd1366c6bdfe01c52777611e4bf",
    "complete": true,
    "required_boundary_events": [
      "STATE_SNAPSHOT",
      "MESSAGES_SNAPSHOT"
    ]
  }
}
```

Remaining lines are strictly increasing, nondecreasing-time records:

- `kind: "run_input"` contains the redacted `threadId`, new `runId`, optional
  orthogonal `parentRunId`, and optional `resume` entries;
- `kind: "event"` contains a `streamId` and one supported AG-UI event.

`streamId` is a program-owned transcript sidecar, not an AG-UI wire field.
State, message, tool-stream, and `RUN_ERROR` events do not all carry
`threadId`/`runId`, so the sidecar binds them to the stream whose
`RUN_STARTED` supplies that identity. This makes interleaved concurrent streams
auditable without treating file adjacency as run identity.

`required_boundary_events` is also a sidecar. The AG-UI draft requires any
state needed for resume to be emitted before the interrupting `RUN_FINISHED`,
but only the program knows which state is needed. The fixture declares whether
`STATE_SNAPSHOT`, `MESSAGES_SNAPSHOT`, or both are required. MCPAudit verifies
that each appears on the interrupted run’s own stream before its terminal
interrupt event.

Supported event projections are:

- `RUN_STARTED`, `RUN_FINISHED`, and `RUN_ERROR`;
- `STATE_SNAPSHOT`, `MESSAGES_SNAPSHOT`, and `STATE_DELTA`;
- `TOOL_CALL_START`, `TOOL_CALL_ARGS`, `TOOL_CALL_END`, and
  `TOOL_CALL_RESULT`.

The projection deliberately excludes text content and unrelated event families.
Unsupported or unprojected content is `UNKNOWN`, never silently dropped.

## Immutable reducer

Each record produces a new frozen reducer state. Interrupt instances are keyed
by thread, source run, and interrupt ID, and end in one of:

- `open`;
- `resolved`;
- `cancelled`;
- `superseded`; or
- `expired`.

The report exposes deterministic open/resolved/cancelled/superseded/expired
counts plus the ordered interrupt state. Payloads, messages, state bodies, and
tool-result content are never copied into findings or reports.

## Stable rules

| Rule | Severity | Observable contradiction |
| --- | --- | --- |
| `AGUI000` | unknown | Transcript or response schema is malformed, incomplete, unsupported, or causally unverifiable |
| `AGUI001` | high | Resume uses the wrong thread, reuses the interrupted run ID, omits a required resume, or binds to a stale/mixed source run |
| `AGUI002` | high | Response set is partial, extra, or contains more than one response for an interrupt |
| `AGUI003` | high | Payload violates `responseSchema`, the bounded schema is unsupported, or tool-call identity is missing/re-emitted/mismatched |
| `AGUI004` | high | A declared required state/messages snapshot is absent from the interrupted stream before `RUN_FINISHED` |
| `AGUI005` | high | An exact `(threadId, interruptId, status, payload)` replay is observably applied by another run instead of deduplicated or rejected |
| `AGUI006` | high | An expired, superseded, terminal, cancelled, or already-resolved interrupt is reopened or an identifier is reused |

`AGUI002` findings carry distinct `kind` values:
`partial_response_set`, `extra_response`, and `duplicate_response`.
`AGUI003` similarly distinguishes schema and tool-identity contradictions.

The bounded `responseSchema` profile supports JSON types; object
`properties`, `required`, and Boolean `additionalProperties`; array `items` and
bounds; scalar bounds; `enum`; and `const`. `$ref`, composition, conditional,
regex, and other unreviewed constructs do not pass. They produce
`AGUI000/unsupported_schema` and an `unknown` verdict. The complete declared
schema shape is traversed when the interrupt is declared, including schemas on
still-open or cancelled interrupts and optional properties or array item
schemas that a supplied response does not exercise. JSON equality preserves the
boolean/number distinction. Decimal literals are accepted only when their value
is exactly representable in binary64; an inexact or non-finite literal is
`UNKNOWN`, never silently rounded into a passing comparison.

Tool-call interruptions require an observed
`TOOL_CALL_START` → `TOOL_CALL_ARGS` → `TOOL_CALL_END` sequence. A successful
resolved resume requires exactly one matching `TOOL_CALL_RESULT` before any
non-error terminal, including a subsequent interrupt. A result may not precede
the tool-bound interrupt. Duplicate, out-of-order, unbound, premature, or
missing tool events cannot pass. `RUN_ERROR` reopens a pre-application attempt
for a legitimate retry, but a result-bearing attempt cannot be treated as
unapplied or silently reopened.

## Limits and rejection

The scanner enforces:

- 4 MiB per fixture;
- 5,000 transcript records;
- 256 KiB per JSONL record;
- 24 levels and 50,000 nodes per JSON value;
- 8 KiB per string;
- 1 MiB aggregate snapshot/state projection;
- 128 resume entries and 128 interrupts per outcome;
- 4,096 interrupt declarations across the whole transcript;
- 12 levels, 1,000 nodes, and 128 properties/items for the supported schema
  evaluator.

It rejects a non-`.jsonl` path before opening it, then accepts only a regular
non-symlink file and binds the read to one opened file identity. It rejects
inexact or non-finite JSON numbers plus unsafe or credential-looking
keys/values with a generic error. Credential matching runs on decoded JSON
strings as well as raw bytes, so Unicode escaping cannot bypass rejection.
`.env`, credential stores, OAuth state, keychains, cookies, browser profiles,
raw logs, user content, production traces, and private transcripts are outside
the input contract and must never be supplied; a `.jsonl` suffix is not a claim
that arbitrary content is synthetic or safe.

## Fixture corpus

`tests/fixtures/agui_interrupt/` contains vulnerable/negative/near-miss
triplets for `AGUI000` through `AGUI006`, plus focused variants for stale
attempts, extra and duplicate response entries, tool-call mismatch, and an
unsupported upstream version.

The corpus covers:

- parallel interleaved runs with correct causal IDs;
- partial, extra, and duplicate response sets;
- wrong thread and stale source-run binding;
- schema mismatch and tool-call identifier continuity;
- missing/wrong-stream boundary state;
- duplicate delivery, explicit replay rejection, and benign same-run retry;
- expired resume application versus explicit expiry rejection;
- malformed, truncated, and unsupported transcript coverage.

## Claim ceiling

A passing report means only that the supplied program-owned synthetic
transcript contains no contradiction covered by `AGUI001`–`AGUI006` and no
known ambiguity covered by `AGUI000`.

It does **not** prove:

- framework-internal checkpoint or coroutine correctness;
- transport ordering, delivery, or exactly-once behavior outside the supplied
  transcript;
- browser or UI quality;
- human identity, understanding, consent, or authorization effectiveness;
- durable workflow recovery;
- tool side effects or end-to-end agent safety.

The analyzer is finite static assurance, not a workflow engine or an AG-UI
implementation.
