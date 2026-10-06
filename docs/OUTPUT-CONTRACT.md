# Output Contract

MCPAudit reports are designed for local review and CI ingestion. Keep this
contract stable unless a release note calls out a breaking change.

Human-facing terminal text displays untrusted Rich markup literally and removes
ESC-led sequences and C0/C1 controls, except tabs and newlines. HTML text removes
the same controls before HTML escaping. Stdio server stderr is captured in a
bounded 4 KiB tail; debug logging emits the sanitized, redacted tail once after
the session ends. JSON and SARIF data, fields, and schema versions are unchanged.

For stable `2.x`, compatible minor and patch releases may add optional JSON
fields. Consumers should ignore unknown fields and should not fail when optional
fields are present. Existing stable fields should only be removed or renamed
with a release-note deprecation window and a breaking-version boundary.

## Safe review entry points

`check --json` (and bare `mcp-audit --json`) emits only the existing redacted
`AuditReport` JSON on stdout. Diagnostics and artifact notices use stderr in
this mode. `check --output-json FILE` writes the same document; `--sarif FILE`
and `--html FILE` use the existing generators. No report field or
`schema_version` changes for these entry points. Legacy `scan --json PATH`
continues to write a file and retains its existing output behavior.

Bare invocation runs the static `check` path. `--config FILE` excludes discovery
unless `--include-discovered` is explicit. Saved overrides and remembered
preferences are not loaded; an explicit policy evaluates evidence without
enabling extra checks. Connections require `--connect --server CLIENT:SCOPE:NAME`
and exactly one matching entry with no collected config diagnostics. Setup and
artifact-write errors exit 1; artifact path validation errors exit 2 before any
artifact is written. A failed policy exits 2 after requested artifacts
and JSON stdout have been written. Exit 0 does not certify security.

Both `check` and legacy `scan` reject artifact destinations that alias any
encountered configuration or policy input, or another artifact destination.
Legacy `scan` also protects its override input. Validation covers resolved
symlinks and hard links, including empty or malformed discovered configs;
the error names the output flag. Existing distinct artifact files may still
be overwritten. Report fields and `schema_version` are unchanged.

Discovery reads only supported adapter candidates and the selected project
(cwd by default, `--project PATH` to select another). It skips symlinks, rejects
special files, and limits each file to 1 MiB, nesting to 64, containers to
20,000, and the review to 1,000 server entries. Explicit config selection may
resolve a symlink to a regular file. Skipped/malformed discovered files produce
config-health findings and partial coverage; an invalid explicit file is a
setup error. `inspect` lists identities and source statuses without connecting.
Absent discovered candidates are listed as `absent`, produce no config-health
finding, and do not reduce coverage. Existing unreadable or malformed files
remain diagnostic, including a selected Claude project entry that is not an
object. Config diagnostic summaries retain the redacted reason also in `details`.
`demo` uses the packaged copy of the synthetic `examples/sandbox` config only.

## Project config connection coverage

`audits[].server.scope` is an additive `workstation|project` field (default
`workstation` for older entries without project metadata). Cwd `.mcp.json`, cwd
`.vscode/mcp.json`, and Claude Code `projects.*.mcpServers` entries are tagged
`project`. Existing `project_path` values and `schema_version = 1` are unchanged.

Project entries retain config-inferred permissions and `connection_status:
"skipped"` unless `ScanOptions.connect_project_configs` is true. CLI `scan` and
`watch` expose this as `--connect-project-configs`; `--skip-connect` takes
precedence over the opt-in. `pin`, pin refresh, and all `serve` tools use the
same project-skipping default. Workstation entries still connect by default.
A project-only scan that skips all entries has `connection_mode: "skipped"`;
a mixed scan that attempts workstation connections has `"attempted"`.

Each project entry withheld by the scope guard emits a structured warning with
`code: "project_config_not_connected"`, `check: "connection"`, and its name in
`servers`. Its message includes the exact unspawned command/args, shell-quoted
with credential values redacted before quoting. Remote entries show their
redacted endpoint instead. Warnings also appear on the CLI console, but the
engine remains silent for library/MCP callers without a console. Explicit
`--skip-connect` never spawns, even with the project opt-in.
All SARIF profiles retain this warning as an invocation notification with
descriptor ID `MCP-PROJECT-CONFIG-NOT-CONNECTED`, its redacted message, and
the warning fields in `properties`. Coverage warnings, including
`project_config_not_connected`, are returned by `scan_mcp_servers` and the
`get_*_findings` tools' `warnings` key. `get_high_risk_servers` retains its
legacy JSON list of `name`/`score` objects and does not return warnings; callers
needing coverage information must use those warning-bearing tools.
`check_server` retains its audit fields and adds `warnings`.

## Missing tool annotations

`audits[].annotations_missing` is an additive boolean, false by default for
older reports. It is true when a listed tool omits `openWorldHint`, or omits
`destructiveHint` without declaring `readOnlyHint=true`. No listed tools means
false; config-only or failed listings do not imply annotation coverage.
`schema_version` remains 1. Existing annotation coverage fields are unchanged.

Missing hints no longer create permission findings or affect numerical scores
and policy gates. They produce one per-server terminal FYI and SARIF `MCP005`
`note` with `properties.kind: "annotations_missing"`, `target_type: "server"`,
and `severity: "low"`. Its stable fingerprint uses the existing algorithm with
namespace `MCP005/annotations_missing` and an empty tool target, so it cannot
collide with a genuine `MCP005` tool finding. The old default rows are consolidated.
Genuine capability rule IDs, tool-target fingerprints, and SARIF alert levels
retain compatibility, including the former annotation contribution when
selecting those levels. Retained tool/category findings also preserve the
former declared-confidence warning, even when independent keyword evidence
has lower confidence. Operator-removed findings are not restored. The note
is always `note`, independent of server risk.
It is informational metadata, not a reduced-coverage scan warning.

`audits[].permission_alert_score` is an additive nullable score (0–10) used
only to select genuine permission SARIF levels. The engine calculates it with
the legacy annotation contributions and the same operator overrides applied
to permission findings. It does not change `risk_score` or policy gates and
survives JSON round trips. Older reports default to null; SARIF retains its
annotation-based compatibility calculation when this score is unavailable.

`readOnlyHint=true` alone creates no `file_read` finding. Independent file
keyword evidence is retained, as are explicit positive network/destructive
declarations. A zero score is not a runtime safety claim.

## Annotation contradictions

`audits[].annotation_findings` is an additive list, empty by default (including
when reading older reports). Its entries contain `kind:
"annotation_contradiction"`, `tool_name`, `hint`, `declared_value`, `category`,
`confidence`, `severity`, `evidence`, `field_paths`, and computed `rule_id`,
`title`, and `remediation`. `schema_version` remains `1`; the existing
permission category and confidence vocabulary is unchanged.

MCP043 compares explicit served hints against existing keyword evidence at
MEDIUM or HIGH confidence. `readOnlyHint=true` contradicts `file_write` or
`destructive`; `destructiveHint=false` contradicts `destructive` only when
`readOnlyHint` is not true; `openWorldHint=false` contradicts `network` or
`exfiltration`. Each contradicted hint/category pair produces one finding.
Null hints, LOW keyword evidence, and absence of a keyword capability do not
produce contradictions. No behavioral, idempotence or intent inference is added.

Severity is HIGH for destructive evidence and MEDIUM otherwise. SARIF maps
these to `error` and `warning`, respectively, independently of the composite
score. Existing global `fail_on.severity` and permission `fail_on.permissions`
thresholds (including server overrides) gate the findings. Contradictions
appear in JSON and SARIF and add no separate numerical score; the restored
keyword permissions use existing scoring. Served hints retain their canary
eligibility veto. See [SCORING-MIGRATION.md](SCORING-MIGRATION.md).

## Report Redaction

Terminal, JSON, SARIF, HTML, and `serve` tool outputs use
`AuditReport.redacted()` to replace likely credentials with the literal
`<redacted>` token. This always applies, independently of `scan --redact`.
It covers secret-name assignments (including env-style names), secret
flag/value pairs in argv and text, bearer/basic credentials, and common
GitHub, OpenAI/Anthropic, Slack, AWS access-key, JWT, GitLab and npm token
shapes. Quoted JSON/dict assignments inside strings are covered, as are string
dictionary values under secret-named keys and string literals in a secret schema
property's `default`, `examples`, and `const`; non-string values and structure
are retained. Inline secret argv assignments redact the whole remainder of the
element. A secret flag does not consume the following argv element when that
element starts with `-`, so gained flags remain visible to provenance checks.
In any `scheme://` URL, userinfo, every query parameter value (including
non-secret parameters), and the entire fragment are redacted; query names,
hosts, ports and path shape remain visible. Userinfo extends through the last
`@` before a path, query or fragment boundary. Secret-named assignments within
each path segment are redacted. Enclosing secret assignments and flag/value
pairs redact their entire URL value before standalone URL spans are protected
from generic named-assignment matching, including secret-named hosts.
Nested `scheme://` URLs within paths are scrubbed independently. A secret-named
path assignment whose value is a URL redacts that whole value, including its path.

Provenance comparisons redact both sides. Changes confined to query values or
fragments therefore do not report drift, even for non-secret endpoint options;
this is an accepted limitation, like secret rotation. Query-name, host, port
and unredacted path changes remain distinguishable.

Secret-name matching recognizes token, API key, secret, password/passwd/pwd,
credential, signature, private/access key, session, authorization/authentication
and separator-delimited auth/sig components. `author`, `authority`, `oauth_callback_port`, plural
`tokens` (such as `--max-tokens`), `tokenizer` components, and separator-delimited
`session-name`/`session_name` labels remain visible; `session_id` stays secret.
Environment variable values are never read; env/header key-name
lists are retained.

Static metadata excerpts redact the complete source field before selecting
context. Match offsets follow credential replacements; a match inside a
redacted value includes the replacement token. Invisible codepoints in evidence
are rendered as `‹U+XXXX›`, including JSON `matched_text`; source metadata and
finding field paths retain their existing shape. The same helper protects
credential-target extracts, schema-property evidence, SSRF parameter/authority
evidence, and field text copied into escalation summaries and drift details.
Permission keyword evidence remains the rule vocabulary, not source excerpts.
Phrase evidence remains withheld when full-field credential matching detects
credentials, including after Unicode normalization. Runtime result and prompt
body excerpts remain withheld. All field excerpts are withheld if normalization
reveals a credential that raw redaction missed; serialized metadata strings use
the same withholding protection. Raw match indices are clamped to the field
bounds before redaction and extraction. No report field or schema version changes.

`scan --redact` additionally scrubs hostname, home-path usernames and matching
server-name text in shared file reports, with the existing stable server
aliases. Terminal output retains identifiers. Dictionary keys are not scrubbed.
Credentials are redacted before identifier aliases can replace secret flag names.
Report fields and `schema_version` are unchanged. Credential redaction is
best-effort pattern matching, not a guarantee that arbitrary or obfuscated
secrets are removed. Review reports before sharing them.

The config-only dictionary API always redacts credentials; its `redact=False`
option skips only identifier scrubbing. Pin tool snapshots redact credentials
while retaining hashes computed over the raw canonical tool metadata.
Escalation compares credential-redacted descriptions and schemas on both sides,
including legacy raw snapshots, so changes confined to redacted spans do not
produce escalation findings. Raw tool-schema hashes still detect metadata drift.
Pin launch snapshots apply the same argv and URL rules by default. See
[`PIN-MAINTENANCE.md`](../maintainers/PIN-MAINTENANCE.md) for the raw-argument escape hatch
and provenance comparison semantics.

## Synthetic performance measurements

The hostile-server test harness writes separate `timing.json` and `metrics.json`
artifacts; these are not `AuditReport` fields and do not change `schema_version`.
Alongside existing timing and process totals, additive coverage fields are:

- `analysis_invocations` and `analysis_tool_counts`: the number of permission
  analyzer calls and the tool count passed to each call, in invocation order.
- `process_roles`: the `server` or `child` role from each recorded PID ledger.
- `file_read_tools`: tool names with `file_read` findings, grouped by audit in
  report order.

Description gates require analyzer coverage and expected findings; the orphan
gate requires both server records and the child record. See the
[hostile-server threat model](HOSTILE-SERVER-THREAT-MODEL.md) for limits.

## Exit Codes

- `0`: scan completed and no configured policy gate failed.
- `1`: command setup failed, such as invalid client or policy config.
- `2`: artifact path validation failed before any artifact was written, or the
  scan completed and requested report artifacts were written but `--policy` failed.

Subcommands with standalone experimental contracts document their own exit
codes below; they do not change the stable scan exit contract.

## Session Resume Fault Lab v1 (experimental)

`mcp-audit session-resume` is separate from `AuditReport`. Its strict contract
identifiers are:

- `mcpaudit.session-resume.scenario.v1`;
- `mcpaudit.session-resume.transcript.v1`;
- `mcpaudit.session-resume.report.v1`; and
- `mcpaudit.session-resume.suite-report.v1`.

Authoritative schemas are emitted by `session-resume schema scenario`,
`transcript`, `report`, and `suite-report`. Canonical JSON is UTF-8, compact,
key-sorted, and terminated by one newline. It contains the scenario SHA-256,
protocol profile, exact logical-time transcript, assumption provenance,
actionable `MCPSR000`–`MCPSR009` findings, independent delivery-safety states,
and the fixed claim ceiling
`local_model_observations_only_exactly_once_unproven`.
Supplied session identifiers are bearer-like input and are serialized only as
deterministic report-local pseudonyms (`session-ref-001`, ...). Result delivery
counts are correlated per request across distinct event IDs, so one request's
duplicates cannot mask another request's missing result. At-least-once support
requires completion evidence for every accepted request, and a dropped result
remains provisional when a later valid replay delivers that same event. Supplied
files are revalidated by device, inode, size, and nanosecond modification time
after the bounded descriptor read.

`session-resume run` exits `0` for a valid replay, including an intentionally
faulty scenario, and `2` for selection or input-contract failure. It has no
network or output-file mutation path; readable or JSON reports go to stdout.
The standalone contract does not add fields to the stable scan JSON schema.

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
- `coverage` — additive map of check names to `{state, reason}`; see below.
- `policy_result`

Tool entries retain all existing fields and add nullable `title`, `output_schema`,
`icons` (a list of JSON icon objects), and `meta` (the served `_meta` object).
`schema_version` remains 1. Pin hashes use `mcpaudit.tool-surface.v2`: default-filled
annotations, omitted null/empty optional fields, served schemas, sorted compact
UTF-8 JSON with a trailing newline and rejected NaN/Infinity. Canary tool
comparisons use the same normalized tool form and serializer. Legacy pins still
compare only name, description and input schema with their original v1 bytes;
scans never upgrade them. See [Pin Maintenance](../maintainers/PIN-MAINTENANCE.md) for migration.

Escalation findings add `kind: annotation_delta` and an `annotation_changes`
list of hint names (empty for other kinds). This is HIGH `MCP018` for
readOnlyHint true→false, destructiveHint false/absent→explicitly true, or
openWorldHint false→true. Hint removal uses MCP defaults. Uncovered legacy
annotations do not establish deltas. These hint names also appear in terminal,
HTML, SARIF result properties and `get_escalation_findings` output.
`pin --refresh --json` adds `uncovered_fields` rows with `tool_name`, `field`
and `summary: "not previously covered"` for each newly covered v1 tool field.

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

### Agent-visible text and prompt arguments (additive)

`prompts[].arguments` remains the ordered list of argument names. The optional
`argument_details` list adds `{name, description, required}` for each argument,
in server order. Description and required are nullable, preserving an omitted
SDK flag rather than inventing one. Older reports load with empty details;
static injection checks then fall back to the legacy names.

Static tool injection checks inspect name, description, `annotations.title`,
and every input-schema string leaf, including nested metadata, definitions,
defaults, enums, and examples. No references are fetched or decoded. Existing
top-level property-name keyword checks are retained. Permission inference also
inspects reachable nested property names through the bounded SSRF schema walker,
including objects, array items, composition branches, and same-document `$ref`
targets. Unreferenced definitions do not contribute property-name matches;
their string leaves remain part of the separate agent-visible text scan.
Tool name and description permission weights remain 3 and 2; property names
and the added text have weight 1. HIGH confidence still requires a score of 6.
Annotation suppression behavior is unchanged.

`injection_findings[].field_path` is an optional JSON Pointer into the report
object for a tool, prompt or resource (for example `/annotations/title`,
`/input_schema/properties/options/description`, or
`/argument_details/0/description`). It is null for older findings, legacy
resource phrase findings, and runtime result/body findings. `permissions[].field_paths`
lists all matching tool field pointers for an aggregated keyword finding;
annotation findings and legacy reports default to an empty list. Existing
evidence strings are retained.

Text matching for static injection, runtime result/body rules and shadowing
uses shared NFKC, removal of `Cf` format characters, Unicode tag-block characters
(U+E0000–U+E007F) and variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF),
then a curated confusable fold. This does not decode tag payloads.

`OBFUSCATED_METADATA` is a MEDIUM structural injection finding (SARIF `MCP008`).
Its description names the codepoint classes and source field pointer.
Invisible classes trigger independently of phrase matches; curated Greek or
Cyrillic confusables trigger when mixed into a Latin-shaped word. Pure non-Latin
names, ordinary accented Latin text, and NFKC compatibility changes alone do
not trigger this anomaly. Runtime findings describe `/body` and retain the
existing withheld-excerpt marker and null `field_path`.

Source capability fields retain their original Unicode codepoints rather than
the matching form. Static `matched_text` evidence uses full-field credential
redaction before slicing and displays invisibles as `‹U+E0020›`-style markers
in JSON as well as terminal, HTML, and SARIF. Other source values in JSON and
SARIF structured properties retain their existing representation. No existing
field is removed or renamed and `schema_version` is unchanged.

Property-name evidence points to that property's schema object. Pointer tokens
escape `~` as `~0` and `/` as `~1`.
Nested property-name matches also add `schema property '<pointer>'` to existing
keyword evidence. Repeated references to the same schema property are counted
once. The shared property walker visits at most 2,048 schema nodes, descends at
most 64 levels, and admits at most 4,096 properties; external references are
never fetched. Existing fields and `schema_version` are unchanged.

Incomplete property traversal produces `warnings[]` with
`code: permission_schema_incomplete` and `check: permission_analysis`.
Messages contain only fixed reason codes: `node_budget_exceeded`,
`depth_budget_exceeded`, `property_budget_exceeded`, `unresolved_reference`,
`unsupported_dynamic_reference`, or the fallback `schema_traversal_incomplete`.
Reference text is not copied into these warnings. Findings from the inspected
portion are retained. Escalation comparison collects the same status from both
current and pinned tool schemas and emits the warning with
`check: escalation_check` when either traversal is incomplete.

The separate agent-visible text extractor admits at most 256 text fields per
tool, 16,384 characters per field, and 65,536 characters in total. Its schema
traversal visits at most 2,048 nodes, descends at
most 64 container levels, and limits each field pointer to 2,048 characters.
Cycles, over-budget branches, and oversized paths are skipped; long fields are
truncated. Prompt static injection text uses the same field and character caps.
Exhausted budgets produce `warnings[]` with `code: agent_text_incomplete` and
`check: agent_visible_text`; findings within the inspected prefix are retained.
Clean findings under this warning do not establish complete text coverage.
The canary rejects tools with incomplete text inspection, even when explicitly
marked safe. Required-argument prompt skip warnings name the prompt and required
arguments without providing or guessing argument values.

These additions keep `schema_version` unchanged.

### Runtime canary fields (additive)

`scan --canary-check` uses the existing `AuditReport` contract and scan exit
codes. Each exercised audit includes `canary` with `requested_calls`,
`completed_calls` (successful protocol `tools/call` responses),
`prompt_get_calls` (attempted `prompts/get`, including errors),
`baseline_hash` / `current_hash` (captured surface SHA256),
`status` (`complete`, `partial`, or `no_safe_tools`), and
`warnings`. `complete` means the bounded protocol exercise completed; it does
not establish server safety. Degraded coverage also adds a top-level warning
with `code: canary_incomplete` and `check: canary_check`. Inspect this alongside
connection status; findings already observed are retained on session failure
or timeout.

Additive, optional fields for compatibility with older reports:

- `client_identity`: the presented MCP client name/version, e.g. `mcp-audit/2.8.1`;
  MCPAudit presents this explicit identity on stdio, Streamable HTTP, and SSE,
  in canary and ordinary connected scans. Older reports load with an empty string
  (identity unrecorded), not the current package identity.
- `client_identities`: names/versions whose sessions reached the initial listing,
  in probe order; defaults to an empty list for older reports. The original
  `client_identity` continues to describe the primary session. Stdio canaries
  use two identities by default; HTTP/SSE use one unless `--canary-identities 2`
  is requested. `--canary-identities 1` disables the differential probe. The
  supported count is 1–2. The alternate client advertises roots support whose
  callback returns no roots, without granting filesystem access or sampling.
- `baseline_source`: `pin` when a complete v2 saved tool snapshot is used,
  otherwise `session` (also the default for older reports). V1 pins are not
  promoted. Saved tool snapshots are compared against the initial listing at
  `after_call: 0`, so pre-session changes are HIGH findings even without
  `--pin-check`. Prompt/resource baselines remain the initial session capture.
  Saved credential-redacted snapshots are compared with redacted tool metadata
  at call zero only; subsequent session and identity comparisons retain raw
  surface hashes. A pin-based `baseline_hash` incorporates reconstructed,
  credential-redacted snapshots; `current_hash` retains the live capture hash.
  Pins are never written by the canary. V2 snapshots must contain every persisted
  tool field, including explicit nulls for absent optional metadata. Malformed
  or incomplete snapshots invalidate the saved baseline for that server. Corrupt
  pins produce `pin_baseline_corrupted` and an explicit fallback to the in-session baseline.
- `elapsed_seconds`: wall duration measured with a monotonic clock, from connection
  through session teardown, including failure or timeout; null when unrecorded.
- `call_budget`: K, equal to the unchanged `requested_calls`; older reports infer
  it from `requested_calls`.
- `not_excluded`: limitations, always populated for new sessions, even when
  `status` is `complete` and `warnings` is empty. Stable identifiers in order:

| Identifier | Behavior not ruled out |
| --- | --- |
| `time` | Activation after elapsed time |
| `randomness` | Randomly activated behavior |
| `call_count_gt_budget` | Activation after more than K tool calls |
| `client_identity` | Different behavior for another client identity |
| `arguments` | Different behavior for other arguments |
| `other_tool_sequences` | Activation by other tool call sequences |
| `later_sessions` | Different behavior in later sessions |

Terminal and HTML show status, completed tool calls / budget, and the human
limitations beside the server verdict. SARIF adds exercised-server summaries
to `runs[0].invocations[0].properties.mcpAuditCanary`, including `server`,
`status`, `completed_calls`, `call_budget`, `client_identity`, `elapsed_seconds`,
`not_excluded`, and the corresponding `not_excluded_descriptions`. New sessions
also include `client_identities` and `baseline_source`. Existing rule IDs remain
unchanged; differential results add the optional `kind` property described below.
Non-canary rendering is unchanged. The SARIF invocation's required
`executionSuccessful: true` denotes completed scan/report
execution, not a clean security verdict.

`drift_findings` includes both saved-pin and session comparisons. Additive
fields are `source` (`pin` by default, `session` for the canary), `severity`
(`medium` by default, `high` for session changes), `after_call` (1-based, null
for saved pins; 0 for initial comparisons), `surface_type` (`tool`, `prompt`, or
`resource`), `surface`
(`tools`, `prompts`, `prompt_results`, or `resources` for sessions), and
`field_changes`. Each change has a JSON Pointer `path` within the capability
and canonical SHA256 `before_hash` / `after_hash`; null means an absent field.
Raw changed values are withheld. `target_type` follows `surface_type`;
the retained legacy `tool_name` / `target_name` also identifies prompts and
resource URIs. The optional `kind` is `IDENTITY_CONDITIONED_SURFACE` for a
difference between the two identities' initial tool/prompt/resource listings
or empty-argument prompt response descriptions and roles, and null for other
drift (including older reports). These findings remain
`source: session`, `severity: high`, and `after_call: 0`; they use SARIF MCP009
with `properties.kind` and a distinct fingerprint. Terminal, HTML, and SARIF
messages name the identity-conditioned difference. Policy drift and HIGH
severity gates both apply. The alternate session lists metadata and gets each
eligible empty-argument prompt once: no `tools/call`, no resource reads, and no
changes to the primary session inventory or hashes. Failed listings are
coverage loss, not removals.
Two selected identities cannot rule out all other identities, so
`not_excluded` retains `client_identity`. The comparison is observational;
legitimate per-client surfaces may also differ. `summary` distinguishes
`prompts` from `prompt_results` (`prompts/get`). Each surface retains its last
successful observation across
failed listings, so later changes and reversions remain detectable. A failed
`prompts/get` retains just that prompt's prior structure while peers are still
compared. Successful prompt listings establish prompt removals. Prompt results
compare descriptions and ordered message roles; rendered content is excluded
from drift and scanned for result injection instead. Prompt argument structure
is compared through `prompts/list`. Unavailable surface categories do not
establish removals. Tools, prompts and resources are always listed in both
modes, so served-but-unadvertised surfaces still reach the static checks; an
unadvertised surface stays debug-only when every listing fails with an ordinary
error and it is never observed. An observed surface that later fails, or an
unavailable surface that later appears, adds a canary coverage warning. Static
analysis retains each surface's last successfully listed inventory across
failures; a successful listing, including an empty one, replaces it.
Listings follow `next_cursor` up to 20 pages; exceeding the limit adds a
coverage warning regardless of advertisement and no partial page set is
admitted. In non-canary scans, prompt/resource page-limit exhaustion adds
`surface_listing_incomplete` to the top-level scan warnings without setting
`connection_error` (`check: null`, affected server named in `servers`). Other
non-canary listing-failure behavior is unchanged. Page-limit warnings use
plain surface labels (for example, "Prompt listing exceeds the 20-page limit;
coverage is incomplete."). The non-canary scan warning also names the server,
advises reviewing the server before trusting the result, and is printed
to the console. Other canary listing errors retain their exception type.

`--canary-calls` bounds tool exercise requests (K), not metadata reads. The
documented exercise request budget includes all `prompts/get`: for P eligible
prompts on each capture and I identities, up to K + P × (K + I) requests, plus
gets on tools-list failure refreshes. Inspect `completed_calls + prompt_get_calls`
for the recorded total; initialize and paginated listing requests are additional.
The session timeout bounds all requests across both identities. Failed tool
requests can leave `completed_calls` below the number attempted;
connection failure and partial status record that
incomplete exercise.

Automatic tool exercise requires `readOnlyHint: true` and no explicit
`destructiveHint: true`. MCP defaults for absent hints are read-only false and
destructive true (the latter applies to non-read-only tools). An operator's
`--canary-safe-tool` mark permits other empty-argument tools, but never overrides
explicit destructive annotations, dangerous keywords, or injection vetoes.

Static free-text matching retains its independent literal phrase rules for
instruction overrides, role overrides, prompt leaks and credential harvesting.
The existing concrete-secret-target summary carve-out also remains. Static/runtime
vocabulary unification is deferred to the 2.9 structural detection and redaction
redesign. These findings report `pattern_name:
"INSTRUCTION_SHAPED_TEXT"`, MEDIUM severity (SARIF `MCP008`), and a description
starting "Experimental heuristic:". Additive `instruction_pattern` identifies
the static pattern and `field_path` is its JSON Pointer, including resource
metadata. `hunt_targets` lists concrete targeted paths/names only, never
values; it defaults to `[]` and `instruction_pattern` defaults to `null` for
legacy, structural, and runtime findings. Static free-text excerpts retain bounded
redacted source evidence after mapping normalized matches back to raw offsets
and rendering invisible codepoints;
phrase excerpts are withheld whenever redaction changes the complete raw or
normalized field, before extracting or truncating evidence. These fields also
appear in SARIF properties and the redacted MCP `get_injection_findings`
projection (`instruction_pattern`, `hunt_targets`, `field_path`), with the same
defaults for legacy findings. New static instruction-text SARIF fingerprints
distinguish the static pattern and field pointer; legacy fingerprints are unchanged.
Terminal and HTML summaries mark concrete metadata secret hunts "Fix now"
without promoting severity or changing policy thresholds or composite risk.
Static phrase matches alone cannot fail a HIGH injection gate. Pin/session
surface deltas and capability escalation retain their existing verdicts.

`ENCODED_BLOB_IN_METADATA` is a LOW structural heuristic (SARIF `MCP008` at
note level): at least 80 consecutive base64/base64url-alphabet characters with
Shannon entropy at least 4.5 bits per character. It reports the run length and
field path, withholds the blob, and never decodes or executes it. HTML comments
retain main's structural hidden-content signal independently of phrase matches.
Bidi/zero-width and fake-role structural
checks retain their existing MEDIUM severity.

Runtime injection findings are experimental free-text heuristics: every one
is reported at MEDIUM (SARIF `MCP008`) with a description starting
"Experimental heuristic:", so they never fail a HIGH gate on their own;
session drift carries the canary's verdict. They add `after_call` and pattern
names `result_instruction_override`, `result_credential_hunt`,
`result_tool_redirect`.
Runtime remediation advises reviewing returned content
or prompt bodies and server behavior, preventing agents from acting on embedded
instructions, and considering server removal; static remediation is unchanged.
Runtime SARIF fingerprints include a runtime marker, target type, and pattern
name to distinguish patterns and static findings on the same target. Repeated
captures of the same runtime pattern keep the same fingerprint. Static
fingerprints remain unchanged. A
concrete secret path or name (for example `~/.ssh`, `~/.aws/credentials`,
`~/.kube/config`, `~/.netrc`, `~/.git-credentials`, shell history, `id_rsa`,
`kubeconfig`, well-known token variables) with a directing verb earlier in
the same sentence is a credential hunt. Generic nouns (credentials, API keys,
secrets, passwords) also need an agent-directed frame or an exfiltration
destination such as "in your next tool call". Known-benign forms such as
`~/.ssh/config` and `.env.example` are excluded; a bare `.env` needs an
outbound verb. Redirects require an agent-directed frame. Tool results keep
the `tool` target type; rendered `prompts/get` bodies are scanned with the same
rules and use the `prompt` target type with the prompt name, reported once per
prompt and pattern at the first capture that showed it (`after_call` is that
capture's preceding call count). `matched_text` is a fixed withheld-excerpt
notice. No result payload is stored in the report. String values in text,
embedded results, and structured content are scanned; binary blobs are not
decoded. Scanned text is capped at 64 KB per result or body; truncation adds a
canary warning and `partial` status.

Session drift uses existing `MCP009` at SARIF `error` level, with `source`,
`severity`, `after_call`, `surface`, and `field_changes` in result properties. Saved-pin
drift remains `warning`. `fail_on.drift` gates either source; the general
`fail_on.severity` threshold also includes session drift. Result injection
uses the existing injection severity gate. No version or schema-version bump
is required for these additive fields.

Setting `fail_on_drift: false` in the Python policy model (YAML
`fail_on.drift: false`) disables the drift-specific gate only. Session drift
can still fail `fail_on.severity: high` (or a lower threshold); saved-pin drift
is excluded from that general severity gate. Per-server drift overrides have
the same interaction.

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
  identify recorded skipped checks. Empty warnings alone do not prove complete
  coverage; also inspect per-server connection status. The report list is
  stably sorted by `(tuple(sorted(servers)), code, message)`; warnings with no
  affected servers come first. Console warnings may remain in completion order.
  Audits stay in input configuration order, and per-server drift findings stay
  in scan/session observation order. Fields:
  - `code` — stable machine key. Current vocabulary:
    `pin_baseline_missing` (check requested but nothing is pinned),
    `pin_schema_outdated` (a compared server has v1 tool entries; annotations,
    title, outputSchema, icons and meta were not covered; original v1 drift
    comparisons remain active, and refresh review is required for v2 coverage),
    `pin_baseline_corrupted` (a pin baseline file exists but could not be
    parsed, or saved v2 canary tool snapshots are invalid or incomplete — materially
    different from "missing", since it can mask a wiped or tampered baseline.
    Parse failures name the file and sanitized error; pin mutations refuse to
    overwrite unparseable files. Invalid or incomplete
    v2 snapshots produce a sanitized per-server canary warning and use the
    in-session baseline without modifying the pin file),
    `pin_baseline_stale` (pinned servers whose baseline predates the capture
    this check compares against; named in `servers`),
    `missing_credential` (e.g. `--llm-analysis` without `ANTHROPIC_API_KEY`),
    `missing_dependency` (e.g. the `anthropic` package not installed),
    `llm_analysis_unknown` (a requested server-level LLM pass detected
    injection, was refused, failed or stopped incompletely at the provider,
    omitted a tool, or returned malformed output; no model findings were
    admitted),
    `option_ignored` (an option passed without the check that consumes it),
    `surface_listing_incomplete` (an initialized non-canary tool, prompt, or
    resource listing exceeded the 20-page limit, advertised or not, or an
    advertised prompt/resource listing was unavailable),
    `description_truncated` (permission keyword or SSRF fetch-verb input
    exceeded the 256 KiB UTF-8 per-field limit; suffix evidence was not inspected).
    The vocabulary is additive — consumers must tolerate unknown codes.
  - `message` — plain-text human summary including remediation.
  - `check` — the scan option whose coverage was reduced, or `null`.
  - `servers` — affected server names; empty means the whole scan.
  An empty list alone does not establish that requested checks ran at full coverage.

### Check coverage

`coverage` records bounded completion independently of findings and scores.
Each entry has `state` (`complete`, `partial`, `not_run`, or `not_requested`)
and a plain-text `reason`. `complete` means the configured check completed for
the configured inputs; it does not establish server safety. `partial` means
some inputs or exercise steps were unavailable, including a mixed fleet of
completed and skipped checks. `not_run` means no usable check ran, and
`not_requested` means the operator did not enable that optional check.

Always-recorded keys are `config_health`, `permissions`, `capabilities`, and
`metadata`. Optional keys match `ScanOptions`: `inject_check`, `ssrf_check`,
`egress_check`, `pin_check`, `trifecta_check`, `shadow_check`,
`escalation_check`, `provenance_check`, `integrity_check`, `verify_artifacts`,
`download_artifacts`, and `llm_analysis`. `runtime_security` records the
bounded `canary_check` exercise. Consumers must tolerate additional keys.
Missing keys and absent or empty coverage maps are unknown, never passed.
Old reports load with an empty map; rendering does not infer completion from
zero findings or connection counts. `schema_version` remains `1`.

Completion requires evidence that the check executed over every applicable
input. A collected configuration parse failure makes every enabled check
`partial`, including configuration health and fleet checks: servers in the
unparseable file are unknown inputs, even if all discovered servers connected.
Optional checks that were not enabled remain `not_requested`.

Config-only scans record metadata and metadata-dependent checks as `not_run`
with reason `connections disabled`; permission inference from configuration
is `partial`. Baseline-dependent checks record missing per-server baselines
as `not_run`. No configured servers leaves server-dependent checks `not_run`.
A canary with no eligible tools has runtime `not_run`; failed or truncated
listings and incomplete exercises are `partial`. Pagination failures never
admit an incomplete page set as an empty, successfully checked inventory.
An `agent_text_incomplete` warning makes permissions and requested injection,
trifecta, and escalation checks `partial` for the affected server, including
checks that consume bounded permission or injection findings. Inventory and
checks that use full metadata are unaffected by this text budget. A pinned
server with an empty tool baseline still has an available `pin_check` baseline.
`permission_schema_incomplete` with `check: permission_analysis` makes permissions
and requested trifecta and escalation checks `partial` for the affected server.
With `check: escalation_check`, only escalation coverage is affected; incomplete
pinned schemas do not degrade current permission coverage. Separate agent-visible
text inspection, metadata inventory, and configuration health are unaffected by
property traversal limits. Checks without an available baseline remain `not_run`.
`description_truncated` makes permissions, capabilities, and requested SSRF,
egress, trifecta, and escalation checks `partial` for the affected server.
This is conservative per-server coverage because the warning does not identify
individual surfaces. Metadata and configuration-health coverage remain complete
when their inspection completed; truncation alone does not reduce coverage for
checks that use full metadata.

Package verification requires current package references with usable baselines
for the exact configured package/version and successful registry hash or byte
verification for every reference. A removed, changed, or floated version with
no applicable baseline is `not_run`; mixed applicability or an unavailable
fetch is `partial`. A nonempty old baseline and an empty findings list do not
prove verification ran. Integrity checks are `partial` when a pinned artifact
cannot be hashed. Runtime completion also requires complete metadata, no
exercise warnings, and completion of the bounded call budget. LLM completion
requires an admissible summary accounting for every candidate tool.

`ServerAudit.connection_status` adds `partial` for an initialized connection
whose metadata listing was incomplete. Existing `connected`, `failed`,
`timeout`, and `skipped` meanings are unchanged. `servers_connected` still
counts established connections, including partial ones; `servers_failed`
still counts failures and timeouts. Inspect coverage for completion.

Terminal output prints `Runtime security: NOT CHECKED` for disabled or unrun
runtime checks and `Metadata checks not run: connections disabled` in
config-only mode. HTML has a Checked strip and an incomplete-coverage banner
for partial or unrun checks. Legacy reports explicitly display unknown coverage.

Policies may opt in with YAML `fail_on.coverage: true` (a boolean), or Python
`PolicyConfig(fail_on_coverage=True)`. This fails on `partial`, `not_run`, or
unknown legacy coverage, independently of severity; `not_requested` checks
do not fail the gate. Coverage violations use existing SARIF `MCP010` and
the existing policy exit code `2`. Existing policies retain their behavior.

`description_truncated` warnings use `check: "permission_analysis"`, name the
affected server, and give a count of truncated fields without including their
contents. The limit applies independently to tool names/descriptions/top-level
parameter names, prompt names/descriptions/argument names, and resource
URIs/names/descriptions/MIME types used for keyword scoring. SSRF fetch verbs
use the same bounded tool-name and description prefixes. Listed metadata stays
intact for reporting, pins and other checks; this is a detector input limit,
not a transport limit. Findings retain their existing shape and confidence
semantics within the inspected prefix; a warning signals reduced coverage.

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
`server_name`, `summary`, `details`, and `remediation`. Additive `config_paths`
lists the source configuration paths, including the path of an unparseable
configuration. Grouped duplicate/conflicting-name findings retain every
applicable source; individual findings retain their own source. Old reports
default to an empty list when source locations are unavailable. Current finding types
include duplicate server names, missing stdio commands, deprecated SSE
transports, shell-wrapper launches, remote endpoints, remote URL arguments,
missing local command paths, project/global server-name conflicts, conflicting
server definitions, package-runner source review, and credential-heavy configs.
These findings do not affect `risk_score.composite`.
Config decoding also emits HIGH `config_parse_failure` for discovered files
that are unreadable, non-regular, invalid, or contain wrong-typed server maps;
HIGH `malformed_server_entry` for rejected individual entries (with
`server_name` when available); and HIGH `duplicate_config_key` when object
keys repeat at any depth. Duplicate-key details give the count and explain
that the last values are retained; earlier definitions were not audited.
Valid sibling entries remain in the scan when individual entries are malformed.
In-memory config-only scans retain the same parsing diagnostics and coverage as
file-based scans, including partial coverage for malformed entries and duplicate keys.
Diagnostics never include entry values or parser source excerpts.
Explicit `--config` files with no supported server map, empty text, invalid
encoding, or other read/parse failures are hard errors. Supported layouts are
`mcpServers`, `servers`, `mcp.servers`, and `projects.*.mcpServers`.
An empty supported map is a valid zero-server scan. These diagnostics use the
existing finding fields; `schema_version` is unchanged.
The presence of `projects` alone is insufficient: at least one project must
contain `mcpServers` when no other supported server map exists.
Policies may opt in to failing on this signal with `fail_on.config_health`; the
default broad `fail_on.severity` shortcut does not include config-health
findings, so existing policy files keep their previous behavior.

The generated JSON Schema for the current model is checked in at
`examples/schemas/audit-report.schema.json` and is tested against the live
Pydantic model.

## Skillscan v1 (`skillscan-report/v1`)

The `skillscan` command statically scans an agent skill directory or MCP-server
bundle (`.mcpb`/`.zip`) offline — it never executes bundle content and never
touches the network — and, with `--json-out`, emits a `skillscan-report/v1`
document. The report is designed to be sealed by an external verifier
(CheckSeal's agent-tooling profile), so its identity and value semantics are
load-bearing.

Stable top-level fields:

- `schema` — the literal `"skillscan-report/v1"`. Bumped only on a breaking
  shape change; additive optional fields do not bump it.
- `scanner` / `scanner_version` — the emitting tool and its version. The version
  flows into a downstream seal's `check.version`.
- `ran_at` — ISO-8601 UTC timestamp.
- `subject` — `{kind, name, digest, media_type}`. `kind` is `skill_bundle`
  (directory) or `mcp_server` (archive). `digest` is the **identity by bytes**:
  for a directory it is the sha256 of the canonical content manifest (NFC posix
  relpaths → per-file sha256, compact sorted JSON; excludes only `.DS_Store`,
  `.git/`, `__pycache__/`; a bare `.pyc` is included; symlinks are refused); for
  an archive it is the sha256 of the archive bytes as distributed. `name` is
  inert display metadata, never identity.
- `ruleset` — `{config_sha256, rules}`. `config_sha256` is the sha256 of the
  canonical rule table and pins which ruleset produced every verdict.
- `checks` — a list of `{id, result, findings, rule_ids, detail}`. `id` is in the
  `scan/` namespace (`scan/injection-patterns`, `scan/obfuscated-egress`,
  `scan/dynamic-fetch-presence`, `scan/permission-surface`).

Value semantics (load-bearing for consumers):

- `result` is `pass` (ran, zero findings), `fail` (ran, findings > 0), or `error`
  (the check itself failed; the reason is in `detail`). A check that does not
  apply is **absent** from `checks` — never emitted as `skip` or `n/a`, because
  absence of a check is not a claim.
- `detail[].excerpt` is credential-redacted (assignments, bearer/basic tokens,
  URL userinfo, and long opaque tokens) before serialization.
- Reports are deterministic for a fixed input apart from `ran_at`.

The authoritative cross-tool contract, including how a verifier re-derives the
subject identity and refuses a report it cannot reproduce, is
`docs/skillscan-report-v1.md` in the CheckSeal repository.

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
See `docs/labs/EVIDENCE-ENFORCEMENT-AGT-FIXTURE.md` for command-specific fields and
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
`docs/labs/AGENT-UI-CONTRACT-AUDITOR.md`.

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
`docs/labs/OAUTH-TRANSCRIPT-AUDITOR.md`.

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
`docs/labs/AUTHORIZATION-POSTURE-ADOPTION.md`.
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
cache. See `docs/labs/CACHE-CONTRACT-AUDITOR.md`.

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
the scenario explicitly selects a local `mark_failed` or `delete` policy. Once
`delete` is applied, the task ID is unavailable and every later observation or
state-changing event is rejected.

The pure engine performs no file, environment, credential, wall-clock, or
network reads. The CLI reads only the exact regular non-symlink fixture path or
uses an in-memory built-in. A passing report proves only supported invariants in
the supplied synthetic scenario; it does not prove live MCP, SDK, host,
persistence, authorization, notification, adoption, interoperability, or
production behavior. See `docs/labs/MCP-TASK-TIME-MACHINE.md`.

## MCP Result Parcel Lab v1 (experimental)

The offline `mcp-audit result-parcel` group is separate from `AuditReport`
schema version `1`. Its strict contract identifiers are:

- scenario: `mcpaudit.result-parcel.scenario.v1`;
- report: `mcpaudit.result-parcel.report.v1`.

`mcp-audit result-parcel schema scenario|report` emits the authoritative
closed JSON Schemas. `analyze` accepts exactly one regular non-symlink JSON
file or one install-safe `--builtin`, renders human output by default, and
emits deterministic canonical JSON with `--format json`. It exits `0` for a
passing suitable or conditional recommendation, `1` for a failed or UNKNOWN
recommendation, and `2` for file-boundary or CLI misuse.

Stable `MCPPARCEL000` records malformed, unsupported, or bounded-out evidence.
`MCPPARCEL001`–`MCPPARCEL013` cover host capability, inline completeness and
size, reference expiry/availability, retrieval authority, content type and
integrity, chunk ordering/completeness/idempotency, progress/result
conflation, partial retrieval, retained cleanup, Tasks final results, and
redaction timing. Every finding names the scenario fields that explain it.
Confidential resource links require enforced principal binding even when the
scenario declares retrieval authorization unnecessary. Unknown task status,
unknown required-redaction stage, and absent observed content type remain
`UNKNOWN`; none can yield a complete suitable recommendation.

The lab profiles MCP `2026-07-28`: inline complete results and resource links
are core; `io.modelcontextprotocol/tasks` is a separately negotiated
extension; chunk streams and progress-as-delivery accept only provider/local
extension classifications. No result, transport, host, credential, remote
resource, or object store is inspected. See `docs/labs/RESULT-PARCEL-LAB.md`.

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

All profiles include `runs[].properties.mcpAuditCoverage` and invocation
`toolExecutionNotifications` for partial, unrun, or unknown legacy coverage.
These notifications describe completion rather than security findings;
`executionSuccessful` does not imply complete coverage.
The default `compatibility` profile retains existing rule and result families.
CLI `--sarif-profile extended` (Python `generate(report, profile="extended")`)
adds configuration-health results with stable IDs `MCP-CH-{FINDING-TYPE}`:
the existing `finding_type` is uppercased, and underscores become hyphens
(for example, `remote_endpoint` becomes `MCP-CH-REMOTE-ENDPOINT`). Findings
retain their severity and remediation. Applicable `config_paths` are emitted
as `locations[].physicalLocation.artifactLocation.uri`, including parse failures
with no parsed server. Results from old reports without source paths omit
locations rather than inventing them. Scores and existing JSON config-health
fields are unchanged.

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
- `MCP043`: explicit served annotation contradicts MEDIUM-or-better keyword capability evidence (HIGH for destructive evidence, MEDIUM otherwise)

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
