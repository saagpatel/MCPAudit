# Output Contract

MCPAudit reports are designed for local review and CI ingestion. Keep this
contract stable unless a release note calls out a breaking change.

For stable `2.x`, compatible minor and patch releases may add optional JSON
fields. Consumers should ignore unknown fields and should not fail when optional
fields are present. Existing stable fields should only be removed or renamed
with a release-note deprecation window and a breaking-version boundary.

## Exit Codes

- `0`: scan completed and no configured policy gate failed.
- `1`: command setup failed, such as invalid client or policy config.
- `2`: scan completed and report artifacts were written, but `--policy` failed.

## JSON Report

The JSON report is the serialized `AuditReport` model. Consumers should treat
unknown fields as additive. Important stable top-level fields:

- `schema_version` — integer version of this report contract (currently `1`).
  Bumped only on breaking shape changes (field removals, renames, retypes);
  additive optional fields do NOT bump it. Consumers wanting runtime drift
  detection should check this field before relying on field access.
- `scan_timestamp`
- `connection_mode` — `attempted` when server connections were attempted,
  `skipped` for a `--skip-connect` config-only scan, or `unknown` when an older
  report omitted the additive field. This prevents zero connected and zero
  failed servers from being mistaken for a clean connected scan.
- `servers_discovered`
- `servers_connected`
- `servers_failed`
- `total_tools`
- `high_risk_servers`
- `audits`
- `config_health_findings`
- `policy_result`

Each audit may include:

- `tools`, `prompts`, and `resources`
- `permissions`
- `capability_findings`
- `injection_findings`
- `ssrf_findings`
- `trifecta_findings`
- `drift_findings`
- `risk_score`
- `non_tool_risk`
- `llm_analysis` — present when `--llm-analysis` was requested. This versioned
  object records `status` (`complete` or `unknown`), a stable `reason_code`,
  `source_trust`, analyzer/model provenance, candidate/analyzed tool counts,
  and the number of admitted findings. `unknown` never means clean.

Each permission finding includes additive provenance fields:

- `source_trust` — `untrusted_server_metadata` for MCP-controlled metadata or
  `operator_override` for an explicit local override;
- `analyzer` and optional `analyzer_model`;
- `analysis_status` — currently `complete` for admitted findings. Failed or
  incomplete LLM output contributes no findings and is represented by the
  audit-level `llm_analysis.status: unknown` summary.

The report top level also includes:

- `fleet_trifecta_findings`
- `shadowing_findings`
- `warnings` — structured coverage warnings (additive in 2.4). Each entry
  records a requested check that was skipped or degraded, so consumers that
  never see console output (JSON pipelines, the MCP server tools) can
  distinguish "checked, clean" from "check silently skipped". Fields:
  - `code` — stable machine key. Current vocabulary:
    `pin_baseline_missing` (check requested but nothing is pinned),
    `pin_baseline_corrupted` (a pin baseline file exists but could not be
    parsed — materially different from "missing", since it can mask a wiped
    or tampered baseline; the message names the file and parse error, and
    pin mutations refuse to overwrite such a file),
    `pin_baseline_stale` (pinned servers whose baseline predates the capture
    this check compares against; named in `servers`),
    `missing_credential` (e.g. `--llm-analysis` without `ANTHROPIC_API_KEY`),
    `missing_dependency` (e.g. the `anthropic` package not installed),
    `llm_analysis_unknown` (a requested server-level LLM pass detected
    injection, was refused, failed or stopped incompletely at the provider,
    omitted a tool, or returned malformed output; no model findings were
    admitted),
    `option_ignored` (an option passed without the check that consumes it).
    The vocabulary is additive — consumers must tolerate unknown codes.
  - `message` — plain-text human summary including remediation.
  - `check` — the scan option whose coverage was reduced, or `null`.
  - `servers` — affected server names; empty means the whole scan.
  An empty list means every requested check ran at full coverage.

`risk_score.composite` is tool-centered. `non_tool_risk` is an additive
prompt/resource triage signal and does not change `risk_score.composite`.
`non_tool_risk` may be `null` when a scan finds no prompt/resource capability or
injection findings.

`ssrf_findings` is an additive per-audit list populated only with `scan
--ssrf-check`. It flags tools and resources whose interface lets a caller steer a
server-side request target (URL/host parameters paired with fetch verbs, or
caller-templated remote resource hosts). It is static and schema-derived — no
request is issued and no credential value is read — and does not affect
`risk_score.composite`. Policies may opt in with `fail_on.ssrf`; the broad
`fail_on.severity` shortcut does not gate SSRF, so existing policy files keep
their previous behavior.

`config_health_findings` is an additive top-level list for pre-connection config
diagnostics. Findings include `finding_type`, `severity`, optional
`server_name`, `summary`, `details`, and `remediation`. Current finding types
include duplicate server names, missing stdio commands, deprecated SSE
transports, shell-wrapper launches, remote endpoints, remote URL arguments,
missing local command paths, project/global server-name conflicts, conflicting
server definitions, package-runner source review, and credential-heavy configs.
These findings do not affect `risk_score.composite`.
Policies may opt in to failing on this signal with `fail_on.config_health`; the
default broad `fail_on.severity` shortcut does not include config-health
findings, so existing policy files keep their previous behavior.

The generated JSON Schema for the current model is checked in at
`examples/schemas/audit-report.schema.json` and is tested against the live
Pydantic model.

## Experimental fixture enforcement contracts

The `enforcement-fixture` command group is separate from read-only scan
behavior. Its four strict versioned contracts are checked in as:

- `examples/schemas/observed-evidence-v1.schema.json`
- `examples/schemas/policy-recommendation-v1.schema.json`
- `examples/schemas/approved-policy-intent-v1.schema.json`
- `examples/schemas/effective-state-v1.schema.json`

All four use `extra=forbid`, required schema/target identity fields, explicit
UTC timestamp patterns, compact sorted canonical JSON with a trailing newline
for SHA-256 binding, and constrained secret-reference names. Cross-field
timestamp ordering is enforced by the live models. They do not change
`AuditReport` schema version `1`.

Every `enforcement-fixture` subcommand writes exactly one JSON object to stdout.
Diagnostics use stderr. Exit `0` means verified success or verified no-op, exit
`1` means a fail-closed policy/runtime result, and exit `2` means invalid input.
Invalid-input messages are generic so rejected values are not reflected into
stdout or stderr; unexpected exceptions also become one fail-closed JSON object.
See `docs/EVIDENCE-ENFORCEMENT-AGT-FIXTURE.md` for command-specific fields and
the exact target-version policy.

## Proof Before Action contracts

Proof Before Action is a separate strict evidence contract; it does not change
`AuditReport` schema version `1`. The five version identifiers are:

- `proof-before-action.declaration.v1`
- `proof-before-action.observation.v2`
- `proof-before-action.trust-manifest.v1`
- `proof-before-action.capsule.v2`
- `proof-before-action.capsule-index.v2`

The verifier also supports historical
`proof-before-action.observation.v1`,
`proof-before-action.capsule.v1`, and
`proof-before-action.capsule-index.v1` bundles under their original comparison
and offline-report projection. Version families cannot be mixed.

The authoritative JSON Schemas are emitted from the live strict Pydantic models
with `proof-before-action schema CONTRACT`. Unknown fields are rejected.
Optional additive fields may be added within one version. A removal, rename,
retype, requiredness change, evidence-semantics change, or canonicalization
change requires a new contract identifier. New inspection/export writes only
the current versions above; legacy support is verification-only compatibility.
The observation, capsule, and index schemas include JSON Schema conditionals
that reject v2 attempt evidence in v1 observations and reject mixed
capsule/observation or index/capsule version families during offline validation,
matching the live model validators. The observation schema also binds every
attempt rule to its stable surface and ordered operations, enforces state,
support, attribution, provenance, and unknown-reason consistency, and rejects
duplicate rule IDs.

`capsule.json` is canonical JSON with sorted keys, compact separators, UTF-8, one
terminal newline, and no floating-point values. Its payload hash covers the
declaration, observation, comparison, release trust manifest, producer state,
and limitations. `capsule-index.json` binds hashes and byte lengths for the JSON
evidence and offline HTML view, plus subject and producer commits. Internal
hashes prove consistency only. The verifier reports authority as `anchored` only
when the caller supplies a matching independently recorded root SHA-256.
Verification also recomputes the declaration/observation comparison, checks the
trust manifest against the staged subject snapshot, and regenerates the offline
HTML projection. A self-consistently rehashed capsule cannot override those
semantic bindings. `current` or `stale` trust entries must also agree with a
clean committed trust source and its recorded scan/snapshot/evaluation
chronology; `current` additionally requires complete diagnostic-free discovery.
The recorded executable must match `argv[0]`, the argv digest must match the
canonical redacted argv, and both JSON files must already be byte-for-byte
canonical rather than merely parse to an equivalent object.
Untrusted capsule and index bytes are validated in strict JSON mode: stringified
booleans/integers and floating-point substitutes are invalid, never coerced.
Schema or canonicalization failures remain structured verifier results.
Missing staged-subject evidence is always invalid, including parseable legacy-v1
payloads. A complete observer's transient filesystem or database attempt counts
as an observed effect even when it leaves no persisted delta.

Observation v2 adds `attempt_evidence`. New observations emit exactly one strict
receipt for each stable rule:

- `PBA-FS-TRANSIENT-001` / `filesystem.transient_attempt`;
- `PBA-DB-NO-DELTA-001` / `database.no_delta_attempt`;
- `PBA-NET-DESTINATION-001` / `network.requested_destination`;
- `PBA-UNIX-SOCKET-001` / `network.unix_socket`.

Each receipt contains:

- `rule_id` and its fixed `surface`;
- the fixed `operations` covered by that rule;
- `state`: `observed`, `blocked`, `incomplete`, or `unknown`;
- `attribution_confidence`: `high`, `medium`, `low`, or `none`;
- `platform`, `backend`, and `support`;
- one or more provenance rows with `kind`, `source`, and
  `observer_owned`;
- `unknown_reasons` for every `incomplete` or `unknown` state.

The current Docker backend emits all four as `unknown`, confidence `none`, and
support `unsupported`. It records final workspace hashes, SQLite semantic/final
state, available network namespace counter deltas, or the validated observer
contract as bounded provenance without claiming those mechanisms traced the
attempt. If counter snapshots are missing, unavailable, or regressed, the
network-destination receipt uses observer-contract provenance and carries the
exact counter-degradation limitation instead of claiming deltas were collected.
Missing or unresolved receipts add an `unknown` comparison finding. V2 also
adds an `unknown` finding for `observed` or `blocked` receipt claims because no
accepted attempt-trace mechanism exists in this contract version. The offline
HTML projection includes the same rule/state/support/attribution matrix.

That last evidence-semantics change is versioned: it is the v2 comparison and
HTML contract. Historical v1 observations do not accept `attempt_evidence` and
are recomputed/rendered with the original v1 behavior, so an integrity-anchored
v1 bundle remains byte-compatible and verifiable. A v1 bundle is historical
evidence, not a v2 attempt-evidence claim.

`proof-before-action inspect` exits `0` for a passing comparison, `1` for a
blocked or unknown comparison, and `2` when validation or observation cannot
complete. `proof-before-action verify` exits `0` only when every requested hash,
schema, commit, and authority check passes; otherwise it exits `1`. Both commands
write one JSON object to standard output.

## Agent UI Contract Auditor v1 (experimental)

The offline `mcp-audit agent-ui` command group is separate from connected MCP
scans and does not change `AuditReport` schema version `1`. Its strict contract
identifiers are:

- `mcpaudit.agent-ui.mcp-apps-fixture.v1`
- `mcpaudit.agent-ui.a2ui-fixture.v1`
- `mcpaudit.agent-ui.a2ui-message.v0.9`
- `mcpaudit.agent-ui.report.v1`

Authoritative JSON Schemas are emitted with `mcp-audit agent-ui schema
CONTRACT`. Unknown fields are rejected. The emitted A2UI message schema includes
strict discriminated shapes for every component in MCPAudit's fixed synthetic
catalog; duplicate component IDs, invalid JSON Pointer escapes, excessive JSON
nesting, and unsupported nested values cannot become a passing report. The
A2UI fixture manifest is the first line of a program-owned JSONL test artifact;
it is a sidecar and is not an A2UI wire message. Remaining lines accept only
A2UI v0.9 messages under the fixed catalog. MCP Apps/OpenAI fixtures contain
metadata and program-owned audit sidecars only; widget HTML and JavaScript are
never input.

Reports use sorted compact canonical JSON with one terminal newline and no
timestamp or absolute input path. Stable finding IDs are `MCPUI001` through
`MCPUI006`; `MCPUI000` records unsupported or ambiguous constructs with
severity `unknown`. Each finding includes severity, title, target, evidence,
remediation, protocol, host profile, and explicit assumptions. Report verdicts:

- `pass`: supported checks found no contradiction and no ambiguity;
- `fail`: at least one non-unknown rule fired;
- `unknown`: only unsupported or ambiguous constructs remain.

The HTML output is a deterministic escaped projection of the JSON report with
`default-src 'none'`. It has no scripts or active links. The scan command exits
`0` for `pass`, `1` for `fail` or `unknown`, and `2` for an input/output error.
It refuses symlink inputs, implicit output replacement, output/input aliasing,
and JSON/HTML output aliasing. All requested output targets are preflighted
before staging begins. Fixture bytes come from one identity-checked regular-file
descriptor and remain subject to the 1 MiB post-read bound. Output staging and
commit stay relative to opened parent-directory descriptors; without `--force`,
atomic create-if-absent commit prevents a post-preflight file from being
clobbered and rolls back this command's prior sibling artifact on a later
collision.

For A2UI approval and evidence controls, data provenance resolves from an exact
JSON Pointer or its nearest declared ancestor. Missing or explicit-unknown
provenance and out-of-domain evidence/visual state strings are ambiguous, not
passing. OpenAI-profile fixtures reconcile dual standard/OpenAI resource URI,
visibility, widget-domain, and CSP declarations; contradictions are
`MCPUI000`. Every supported external authority is a validated credential-free
HTTPS origin before declaration matching.

A passing fixture report is not evidence about widget bytes, renderer behavior,
host consent, CSP enforcement, server authorization, transport ordering,
sandboxing, authentication, or any real user workflow. A2UI, MCP Apps,
OpenAI-specific extensions, AG-UI, and WebMCP remain distinct; the auditor does
not claim translation or interoperability. See
`docs/AGENT-UI-CONTRACT-AUDITOR.md`.

## MCP OAuth Transcript Auditor v1 (experimental)

The offline `mcp-audit oauth-transcript` command group is separate from normal
MCP discovery and connected scans. It does not change `AuditReport` schema
version `1`. Its strict contract identifiers are:

- `mcpaudit.oauth-transcript.fixture.v1`
- `mcpaudit.oauth-transcript.report.v1`

Authoritative schemas are checked in at
`examples/schemas/oauth-transcript-fixture-v1.schema.json` and
`examples/schemas/oauth-transcript-report-v1.schema.json`, and are emitted by
`mcp-audit oauth-transcript schema fixture|report`. Unknown fields are rejected.
The specification profile is pinned to
`mcp-authorization-2025-11-25+draft-2026-07-28`; the dated draft portion covers
authorization-response issuer validation, issuer-bound client state, and DCR
`application_type` behavior.

Reports use sorted compact canonical JSON with one terminal newline and no
timestamp or input path. Stable finding IDs are `MCPOAUTH001` through
`MCPOAUTH007`; `MCPOAUTH000` represents missing, malformed, redacted,
unsupported, or unverifiable evidence. Each finding contains severity,
`violation|advisory|unknown` outcome, `required|recommended|deprecated|unsupported`
requirement level, title, semantic target, redacted evidence, remediation,
primary references, and assumptions.

Report verdicts are:

- `pass`: no violation or unknown finding; deprecated/recommended advisories may remain;
- `fail`: at least one violation;
- `unknown`: no violation, but one or more bindings cannot be evaluated.

The scan command exits `0` for `pass`, `1` for `fail` or `unknown`, and `2` for
an input/output error. `--json` writes the canonical report. `--sarif` writes a
SARIF 2.1.0 compatibility projection using the existing `mcp-audit` driver and
stable rule IDs; JSON remains authoritative. Output creation uses the same
descriptor-bound, atomic, no-clobber path as the Agent UI auditor.

Secret-bearing fields accept only redaction markers. Findings and errors omit
raw authorization headers, cookies, codes, tokens, secrets, query values,
arbitrary bodies, and input URLs; sanitized parser and CLI exceptions do not
retain the source parse/validation exception as a cause or context. Input is
limited to 1 MiB, 32 JSON levels, 64
observations, 8 metadata documents, 5 recorded redirects, and 2,048 characters
per URL. URLs are never fetched, redirects are never followed, and no network,
browser, OAuth, MCP, account, keychain, or credential-store path exists.

A passing report proves only the implemented binding invariants in the
supplied synthetic transcript. It does not prove token signature validity,
PKCE correctness, client-authentication strength, IdP integrity, consent,
real-world authorization, or production security. See
`docs/OAUTH-TRANSCRIPT-AUDITOR.md`.

## MCP Authorization Posture Adoption v1 (experimental)

The offline `mcp-audit authorization-posture` command group consumes a separate
portable producer contract and does not change `AuditReport` schema version
`1`. Its strict identifiers are:

- input: `McpAuthorizationPostureV1`, contract version `1.0.0`;
- report: `mcpaudit.authorization-posture.report.v1`.

Authoritative schemas are checked in at
`examples/schemas/authorization-posture-input-v1.schema.json` and
`examples/schemas/authorization-posture-report-v1.schema.json`, and are emitted
by `mcp-audit authorization-posture schema input|report`. Unknown fields and
implicit type coercion are rejected.

The review command validates the declared official-Registry binding, public
metadata state, bounded fetch shape, GET-only credential-free capability
boundary, no-authority claim ceiling, and cross-field resource/issuer
consistency. It never re-fetches a URL. A valid `metadata-ready` producer input
becomes `disposition=policy-review-only`; a valid `unknown` input remains
`disposition=blocked`. Stable finding `MCPPOSTURE001` is advisory and
`MCPPOSTURE000` is unknown. Exit `0` means policy-review-only, exit `1` means
blocked, and exit `2` means invalid input or output.

Reports use sorted compact canonical JSON with one terminal newline and bind
the input bytes by SHA-256. They omit producer fetch records and authorization
or token endpoints. `input_provenance=unverified`,
`input_freshness=unverified`, and
`remote_observation_authority=producer-asserted` are invariant. Metadata state
is explicitly `producer-declared-ready|producer-declared-unknown`; schema
validation does not authenticate the producer, timestamp, Registry export,
remote responses, or current applicability. The consumer cannot contact an MCP
endpoint, use credentials, run OAuth, authorize a scan, or change a trust grade. See
`docs/AUTHORIZATION-POSTURE-ADOPTION.md`.
## MCP Cache Contract Auditor v1 (experimental)

The offline `mcp-audit cache-contract` command group is separate from connected
MCP scans and does not change `AuditReport` schema version `1`. Its strict
contract identifiers are:

- `mcpaudit.cache-contract.trace.v1`;
- `mcpaudit.cache-contract.report.v1`.

Authoritative JSON Schemas are emitted with `mcp-audit cache-contract schema
trace|report`. Unknown fields are rejected. The trace binds every event to
explicit sequence and logical-millisecond values, a protocol version,
principal, asserted authorization-context `cache_partition`, method, complete
result-affecting parameters, and response/use/refresh/change-event evidence.
Conflicting principal labels inside one asserted `cache_partition` produce
incomplete `MCPCACHE000` coverage before private cache ordering evidence is
compared.

Reports use sorted compact canonical JSON with one terminal newline and no
timestamp, hostname, platform, duration, random ID, or absolute input path.
The trace digest is computed after sorting events by explicit sequence, so
serialization order does not change output when causal order is unchanged.
Stable finding IDs are `MCPCACHE001` through `MCPCACHE009`; `MCPCACHE000`
records malformed, unsupported, ambiguous, truncated, or bounded-out evidence
with severity `unknown`. Each finding includes severity, requirement level,
title, generated event target, fixed evidence code, remediation, protocol
version, event sequence numbers, and explicit assumptions. Trace-controlled
principal/partition labels, parameter values, URIs, and response bodies are not
reflected into findings.

Report verdicts:

- `pass`: supported list/read checks are complete and no contradiction remains;
- `fail`: at least one non-unknown rule fired;
- `unknown`: only malformed, unsupported, ambiguous, or incomplete coverage
  remains.

If the 2,048-finding bound is exceeded, an
`MCPCACHE000`/`finding_limit_exceeded` marker is emitted and at least one
observed non-unknown finding is retained, preventing output truncation from
downgrading a `fail` verdict to `unknown`.

The scan command exits `0` for `pass`, `1` for `fail` or `unknown`, and `2` for
a file-system input failure. Malformed JSON and strict-contract failures emit
one structured `unknown` report before exit `1`. A stable regular file larger
than 1 MiB is bounded to an inspected 1 MiB plus one sentinel byte and emits
structured `unknown` before exit `1`; its trace digest binds only that inspected
prefix. The input must be a regular non-symlink file and is read through one
identity-checked descriptor. Where the platform exposes `O_NONBLOCK`, the
descriptor uses it so a raced FIFO replacement cannot stall before type
validation.

The analyzer supports MCP `2026-07-28` complete results for `tools/list`,
`prompts/list`, `resources/list`, `resources/templates/list`, and
`resources/read`. It checks required `ttlMs`/`cacheScope`, exact request-key
reuse, private authorization partitioning, explicit TTL/refresh behavior,
validated list/resource notifications, linked page scope, deterministic
unpaginated tools ordering, string-shaped opaque pagination cursors, and
non-cacheable multi-round-trip results. Present non-string `cursor` or
`nextCursor` values produce incomplete `MCPCACHE000` coverage instead of a
passing ordering result; an empty string remains a valid cursor.
`server/discover`, older/future revisions, URI alias/prefix invalidation,
notification delivery to other cache instances, and ordering of other lists
remain explicitly unsupported. An event carrying an unsupported protocol
version produces incomplete `MCPCACHE000` coverage and is not subsequently
graded against current-version cache keys or freshness rules.

`MCPCACHE005` is a SHOULD-level freshness finding, not a claim that MCP always
forbids stale use. A causal exact-key `refresh_error` preserves the protocol's
permission to serve stale data after a failed re-fetch when the error follows
observable expiry or a validated invalidation, only until a later valid
successful refresh supersedes that failed attempt. A passing fixture report
does not prove HTTP caching, performance, server/client/proxy behavior,
authorization, confidentiality, notification delivery, or any production
cache. See `docs/CACHE-CONTRACT-AUDITOR.md`.

## MCP Task Time Machine v1 (experimental)

The offline `mcp-audit task-time-machine` command group is separate from
connected MCP scans and does not change `AuditReport` schema version `1`. Its
strict contract identifiers are:

- `mcpaudit.task-time-machine.scenario.v1`;
- `mcpaudit.task-time-machine.result.v1`.

Authoritative strict JSON Schemas are emitted by `mcp-audit task-time-machine
schema scenario|result`. Unknown fields and implicit type coercion are rejected.
Scenario execution is seed-free and ordered by explicit `(at_ms, sequence)`
coordinates; sequence values must be unique. Duplicate event IDs remain valid
test input, but only the first event is applied and later copies are flagged.

Results use sorted compact canonical JSON with one terminal newline. They carry
the `2026-07-28` protocol profile, final SEP-2663 source revision, as-of date,
scenario digest, null seed, full transition explanations, bounded final task
state, coverage, assumptions, and stable findings `MCPTASK000` through
`MCPTASK008`. JSON-RPC error `data` accepts any bounded JSON value, including
scalars and arrays; arbitrary task result and error payloads are not reflected.

Verdicts are:

- `pass`: supported lifecycle invariants are not contradicted;
- `fail`: at least one supported protocol, design-inference, or local-fixture
  invariant is contradicted;
- `unknown`: only malformed, unsupported, or ambiguous semantics remain.

`task-time-machine run` emits human-readable output by default and canonical
JSON with `--json`. It exits `0` for `pass`, `1` for `fail` or `unknown`, and
`2` for invalid input selection or a filesystem boundary error. A task ending
in `failed` can still produce simulator verdict `pass`; the verdict grades the
scenario's lifecycle consistency, not task success.

The simulator covers task creation, polling cadence, local retry/backoff,
input-required round trips, cooperative cancellation races, expiry, completion,
JSON-RPC failure, duplicate delivery, stale or impossible future observations,
and terminal-state immutability. Retry policy and `work_started` are local
fixture semantics.
Initial `working` and terminal immutability are disclosed design choices where
SEP-2663 is not an exhaustive transition matrix. Expiry remains `UNKNOWN` unless
the scenario explicitly selects a local `mark_failed` or `delete` policy.

The pure engine performs no file, environment, credential, wall-clock, or
network reads. The CLI reads only the exact regular non-symlink fixture path or
uses an in-memory built-in. A passing report proves only supported invariants in
the supplied synthetic scenario; it does not prove live MCP, SDK, host,
persistence, authorization, notification, adoption, interoperability, or
production behavior. See `docs/MCP-TASK-TIME-MACHINE.md`.

## SafeForge Manifest v0

SafeForge uses a separate, additive evidence-envelope contract; it does not
change `AuditReport` schema version `1`. The generated schema is checked in at
`examples/schemas/safeforge-manifest-v0.schema.json` and is tested against the
live `SafeForgeManifest` model.

The v0 contract is intentionally pre-install and read-only. Importing or calling
`mcp_audit.safeforge` does not install dependencies, launch an MCP server, run a
connected scan, evaluate a live policy, grade a server, or publish anything.
Producers populate the manifest; `validate_safeforge_manifest` checks its shape
and the research pipeline's fail-closed semantics.

`consume_forge_receipt` in `mcp_audit.safeforge_consumer` accepts a
`ForgeReceiptV0` payload plus its generated artifact root. It validates the
producer contract, rejects symlinks and any undeclared file, recomputes every
file and tree digest, verifies dependency and launch-config bindings, and then
runs only `scan_config_only`. A successful handoff records these stages, in
order: `source.bind`, `forge.plan`, `forge.generate`, `validate.static`,
`contract.preinstall`, and `audit.config`. Receipt, artifact, dependency, config,
or config-audit warnings block the handoff. The partial manifest remains
`building`; protocol negotiation, sandboxing, connected audit, grading, policy
binding, publication, and final receipt creation are explicitly outside this
consumer.

Before receipt ingestion, coordinators can pass mcpforge's exported JSON Schema
to `lint_forge_receipt_schema` in `mcp_audit.safeforge_contract_linter`. The
linter dereferences and canonicalizes both schemas, ignores annotation-only
changes such as titles and descriptions, and compares their accepted semantic
shape. Exact matches pass. New optional producer fields are classified as
`additive`, but still fail the strict v0 compatibility gate because MCPAudit
rejects unknown receipt fields. Removed fields, required-field changes, version
changes, and constraint changes are classified as `breaking`. The result includes
canonical producer and consumer SHA-256 digests, so a workflow can bind its
compatibility decision without importing or executing generated server code.

Contract schema input is limited to one MiB, receipt input to four MiB, and
schema normalization to local fragment references, 64 levels, and 10,000 nodes.
Malformed, external, missing, cyclic, or oversized schemas return structured
fail-closed output rather than escaping the JSON command contract.

ToolBOM entries bind declared capabilities to an implementation digest and
code-observed filesystem/network behavior. Filesystem access requires the
`filesystem` permission, and observed network destinations must match declared
egress. An unresolved producer security warning is not preinstall-eligible and
cannot be converted into a passed static stage.

The `mcp-audit safeforge-preinstall` command composes those two boundaries. It
requires `--producer-schema`, `--receipt`, `--artifact-root`, `--run-id`,
`--created-at`, and `--coordinator-revision`. Contract linting runs before the
artifact path is inspected. Standard output is always one JSON object: exit `0`
means the contract and preinstall audit were accepted, exit `1` means a
fail-closed contract or preinstall decision, and exit `2` means the command
inputs could not be parsed. The command has no connected, install, sandbox,
grading, policy, publication, or finalization mode.

`mcp-audit safeforge-run` resumes that accepted preinstall envelope through
`sandbox.prepare`, `sandbox.materialize`, `audit.connected`, `trust.grade`,
`runtime.policy.bind`, `publication.dry_run`, and `receipt.finalize`. Standard
output remains one strict JSON object. Exit `0` requires an `eligible` final
manifest; exit `1` is a fail-closed pipeline decision; exit `2` is invalid
input. The runtime command never edits an MCP client, installs on the host,
publishes, or contacts a generated-server endpoint outside its disposable
boundary.

The current research provider is macOS Seatbelt with network fully denied. It
proves isolated HOME/cache/temp state, denial of user-home and mounted-volume
access, keychain denial, locked offline materialization, CPU/memory/disk/process
and wall-time enforcement, process-group termination, and cleanup. Receipts
with credentials or any declared/observed egress are blocked because
redirect-safe hostname allowlisting is not yet proven. Runtime tool names,
descriptions, input/output schemas, annotations, prompts, resources, protocol,
receipt-bound launch configuration, and a bounded synthetic call are compared
before grading.
Generated tests and the connected MCP session run with process creation denied;
the session uses FastMCP's in-memory protocol transport, so the research grade
does not claim that an unrestricted host-side stdio launcher is safe.

Final policy evidence binds the exact artifact-tree and connected-audit
digests. The publication stage is a metadata-only local install-plan dry run.
The final receipt is created only when all thirteen stages are current and
passed; skipped, unknown, stale, failed, or blocked stages cannot finalize.

For deterministic receipt replay, the embedded config-only report replaces four
non-security runtime fields with canonical values: its timestamp is the required
coordinator `--created-at`, hostname is `<canonical-host>`, platform is
`canonical`, and elapsed time is `0.0`. Findings, warnings, coverage, server
configuration evidence, and risk calculations are not normalized. This makes
the report reference and partial manifest stable for identical declared inputs.

Stable v0 identities:

- `contract_id`: `safeforge.pipeline`
- `contract_version`: `0.1.0`
- `profile`: `research-mvp`

The validator distinguishes structural failures from semantic pipeline
failures. Structural failures use `SF-CONTRACT-SCHEMA`; semantic findings use
stable `SF-*` codes for tool identity, attempt history, state transitions,
stage order, final evidence, policy status, grade freshness, and publication
dry-run status. Required stages that are skipped, unknown, stale, failed, or
blocked cannot finalize as eligible.

Manifest models reject unknown fields and permit credential *key names* only.
Artifact references must use portable relative URIs and SHA-256 digests; local
absolute paths and `file:` URIs are invalid.

Finding targets:

- tool permission and drift findings use `tool_name` and additive
  `target_type: "tool"` / `target_name` metadata
- prompt/resource capability findings use `target_type` and `target_name`
- injection findings include `tool_name` for compatibility and additive
  `target_type` / `target_name` fields for tool, prompt, and resource targets
- SSRF findings use `target_type` and `target_name` for tool and resource targets
- trifecta findings use `severity`, `is_fleet`, `leg1_contributors`,
  `leg2_contributors`, `leg3_contributors` (lists of `[server_name, tool_name]`
  pairs), `rule_id`, `title`, and `remediation`; per-server findings live on
  `ServerAudit.trifecta_findings`, fleet findings on
  `AuditReport.fleet_trifecta_findings`
- shadowing findings use `kind` (exact|normalized|homoglyph), `severity`, `name`
  (canonical/colliding tool name), `collisions` (list of `[server_name, tool_name]`
  pairs ordered with the first-configured/presumed-legitimate server first),
  `description`, `rule_id`, `title`, and `remediation`; all findings live on
  `AuditReport.shadowing_findings` (fleet-level only — collisions are inherently
  cross-server); populated only with `--shadow-check`; does not affect
  `risk_score.composite`; policies may opt in with `fail_on.shadowing`

Compatibility rules:

- additive optional fields are allowed in compatible stable releases;
- existing stable fields require a release-note deprecation window before
  removal or rename in a breaking release;
- SARIF rule IDs must remain stable unless a breaking release explicitly
  documents a migration.

## SARIF Report

SARIF output uses stable MCP rule IDs:

- `MCP001`-`MCP006`: permission categories
- `MCP007`-`MCP008`: prompt-injection findings
- `MCP009`: tool schema drift
- `MCP010`: policy gate violation
- `MCP011`-`MCP012`: SSRF findings
- `MCP013`: per-server lethal trifecta (HIGH)
- `MCP014`: fleet-level lethal trifecta advisory (MEDIUM)
- `MCP015`-`MCP017`: cross-server tool-name shadowing (exact / normalised / homoglyph)
- `MCP018`-`MCP019`: capability-escalation ("rug pull") vs pin baseline (capability gain / description-injection gain)
- `MCP020`-`MCP023`: launch-config / provenance drift vs pin baseline (command / args / url / credential key-names)
- `MCP024`: launch-artifact integrity drift vs pin baseline (on-disk binary/script hash change)
- `MCP025`: registry package-verification drift vs pin baseline (npm/PyPI published hash change; network, opt-in)
- `MCP026`: byte-level artifact verification vs pin baseline (downloaded bytes don't match the registry-published hash, or a pinned file changed/added since baseline; network, opt-in)
- `MCP040`: outbound destination outside the egress allowlist (fixed, non-caller-controlled destination; opt-in `--egress-check`)
- `MCP041`: unbounded caller-controlled outbound destination (URL/host parameter or templated host authority; opt-in `--egress-check`)
- `MCP042`: allowlisted destination with residual egress risk (multi-tenant data-bearing API or caller-attachable credentials; opt-in `--egress-check`)

## Compatibility Fixture

The report fixtures in `tests/fixtures/reports/` cover representative connected,
failed, config-only, policy-failed, prompt/resource-heavy, SSRF, and trifecta reports. Tests
validate that fixtures still load through the current Pydantic models, generate
SARIF with the expected stable rules, and match the golden output-contract
snapshot in `tests/fixtures/reports/output_contract_snapshot.json`.

Upgrade compatibility fixtures in `tests/fixtures/reports/legacy/` cover older
report shapes that predate additive prompt/resource and config-health fields.
They also verify that future additive fields are ignored by the current model,
matching the stable compatibility rule for tolerant downstream consumers.

Redacted field-report fixtures in `tests/fixtures/reports/field/` cover mixed,
single-client, and quiet config-only setup shapes from real-world review paths.
The Python parser, Node parser, and dashboard summary examples are contract
tested against compatibility and field-report fixtures so output-consumer
friction can be turned into small regressions before the beta label.

## CI Examples

Write SARIF for GitHub code scanning:

```yaml
- name: Audit MCP servers
  run: mcp-audit scan --sarif mcp-audit.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-audit.sarif
    category: mcp-audit
```

Use JSON plus a local policy gate:

```bash
mcp-audit scan --json mcp-audit.json --policy examples/policies/balanced-team-ci.yaml
```

Exit code `2` means reports were written but the policy gate failed.

Copy-paste workflow examples live in `examples/ci/`:

- `github-code-scanning.yml`
- `generic-json-policy.yml`
- `forge-then-audit.yml`
