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

## Proof Before Action v1

Proof Before Action is a separate strict evidence contract; it does not change
`AuditReport` schema version `1`. The five version identifiers are:

- `proof-before-action.declaration.v1`
- `proof-before-action.observation.v1`
- `proof-before-action.trust-manifest.v1`
- `proof-before-action.capsule.v1`
- `proof-before-action.capsule-index.v1`

The authoritative JSON Schemas are emitted from the live strict Pydantic models
with `proof-before-action schema CONTRACT`. Unknown fields are rejected.
Optional additive fields may be added within v1. A removal, rename, retype,
requiredness change, evidence-semantics change, or canonicalization change
requires a new contract identifier.

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

`proof-before-action inspect` exits `0` for a passing comparison, `1` for a
blocked or unknown comparison, and `2` when validation or observation cannot
complete. `proof-before-action verify` exits `0` only when every requested hash,
schema, commit, and authority check passes; otherwise it exits `1`. Both commands
write one JSON object to standard output.

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
