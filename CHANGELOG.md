# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `proof-before-action` — a local-first CLI that compares a declared action
  boundary with disposable runtime observations, emits versioned JSON schemas
  and an offline evidence capsule, and verifies capsule integrity against
  explicit producer commits and independently supplied root hashes. Unknown,
  stale, masked, unmatched, or unobservable evidence remains non-authoritative.
  Its minimally capable observer protects evidence from the unprivileged,
  capability-free tested command, stops surviving descendants before the final
  archive, and fails closed when command identity, quiescence, or cleanup cannot
  be confirmed.
  Dirty or commit-unbound local mcp-trust sources now downgrade every matched
  entry to non-authoritative, detail-withholding `unverifiable` evidence.
- `pin_baseline_corrupted` warning code — a pin baseline file that exists but
  cannot be parsed now emits its own `ScanWarning` (naming the file and the
  parse error) instead of folding into `pin_baseline_missing`. A corrupted
  baseline can mask a wiped or tampered pin store, which is a materially
  different condition from never having pinned. Extends the strict-write
  honesty from 2.3.0 (`PinFileError` refuses mutations through unparseable
  files) to the read/report path. (#158)

## [2.4.0] - 2026-07-03

### Added

- `AuditReport.warnings` — structured `ScanWarning` entries for every requested
  check that was skipped or degraded (missing/stale pin baseline, missing
  credential or dependency, ignored option). Previously these were
  console-only, so JSON and MCP-server consumers could not distinguish
  "checked, clean" from "check silently skipped". Additive: `schema_version`
  stays `1`; the code vocabulary is documented in docs/OUTPUT-CONTRACT.md.

### Changed

- MCP server `get_*_findings` tools now return `{"findings": [...],
  "warnings": [...]}` instead of a bare findings list, so a caller can tell an
  empty result apart from a check that could not run (e.g. a drift tool called
  with no pin baseline). `scan_mcp_servers` carries the same warnings via the
  report's `warnings` field.

## [2.3.0] - 2026-07-03

### Added

- Added `mcp_audit.engine` — the public scan-engine module. `run_scan()` plus a
  frozen `ScanOptions` dataclass replace the private 24-argument
  `cli._run_scan_core` as the one sanctioned entry point into the scan pipeline
  (discover → connect → analyze → score). The engine is silent by default and
  only renders progress/warnings when a caller passes a rich `Console`, so
  library and MCP-server callers can never leak scan chatter onto
  machine-readable channels.
- Added `schema_version` (currently `1`, exported as
  `models.AUDIT_REPORT_SCHEMA_VERSION`) to `AuditReport` so downstream
  consumers (mcp-trust, shadow-mcp, hosted `mcp_audit.api` callers) can detect
  contract drift at runtime. Additive fields do not bump it.
- Added `mcp_audit.confighealth` — config-health analysis
  (`config_health_findings`, `duplicate_server_config_counts`) extracted from
  `cli.py` into its own importable module.

- Added the `mcp-name: io.github.saagpatel/mcp-audit` registry-ownership marker to
  the README so the official MCP registry can verify PyPI namespace ownership.
- Published `server.json` for the official MCP registry
  (`io.github.saagpatel/mcp-audit`) plus a `mcp-audits` console-script alias, so
  the auditor launches as an MCP server via `uvx mcp-audits serve`.
- Added a public-safe MCP Prompt-Injection Sandbox under `examples/sandbox/`
  with synthetic configs, benign twins, MCPAudit-style config-only findings,
  connected tool metadata fixtures, docs, and public-safety tests.

### Changed

- `mcp_audit.cli`, the MCP server tools (`serve`), `watch`, and
  `mcp_audit.api` are now thin consumers of `mcp_audit.engine`; the MCP server
  tools no longer print engine warnings onto stdout (which carries MCP stdio
  protocol frames), and `pin` flows call the engine directly.
- A missing or unparseable `--config` path is now a hard error (`run_scan`
  raises `ValueError`; the CLI exits with a clear message) instead of printing
  a warning and continuing with an empty server list — a typo'd path can no
  longer degrade into a clean zero-finding report that passes downstream
  gates.

### Deprecated

- `mcp_audit.cli._run_scan_core` is now a compatibility shim that emits a
  `DeprecationWarning` and delegates to `mcp_audit.engine.run_scan`. External
  callers (e.g. shadow-mcp) should migrate to `mcp_audit.engine`.

### Fixed

- Tightened capability keyword matching so patterns match identifier-like
  tokens rather than substrings inside ordinary words, reducing false positives
  such as `port` in `report` or `post` in `postgres`.

## [2.2.1] - 2026-06-27

### Changed

- Refreshed docs and package metadata so the next PyPI package can reflect the
  cleaned public-facing README and stable compatibility wording.
- Softened unsupported false-positive wording in shadowing and escalation
  documentation/docstrings. Findings remain scoped to concrete cross-server
  tool-name collisions or reviewed baseline deltas.
- No scanner behavior, output contract, or policy-gate semantics changed.

## [2.2.0] - 2026-06-20

### Added

- **Programmatic config-only scan API** (`mcp_audit.api`) — `parse_config`,
  `scan_config_only`, and `scan_config_only_dict` run the exact config-only,
  skip-connect scan engine on an MCP client config already in memory (a parsed
  mapping or raw JSON), for hosted callers such as a "paste your MCP config →
  trust score" page. The path never spawns a server process and never makes a
  network request — only declared configuration is statically inferred, matching
  `mcp-audit scan --config <file> --config-only --skip-connect`. The discoverer's
  format handling is shared via `discovery.claude_code.parse_mapping`, and
  `_run_scan_core` accepts a pre-parsed `servers` list so discovery (and all
  filesystem access) is skipped when the caller supplies one. `scan_config_only_dict`
  scrubs host/username identifiers by default and refuses to run inside an active
  event loop.

## [2.1.0] - 2026-06-12

### Added

- **Rule of Two posture** on lethal-trifecta findings — every fired trifecta finding
  (per-server `MCP013` and fleet `MCP014`) now carries an advisory `rule_of_two` posture
  after Meta's Oct 2025 framework: which single leg to drop to break the trifecta, the
  concrete remediation, and the two alternatives. Deterministic heuristic — prefer
  dropping Leg 3 (exfiltration, enforceable via `--egress-check`) when present, else the
  fewest-tools leg. Purely advisory: it never changes *when* the trifecta fires. Renders
  in the terminal, HTML, and SARIF reports. See `docs/TRIFECTA-DETECTION.md`.
- **Egress detection** (`scan --egress-check`, opt-in) — audits *where* an MCP server may
  send data, complementing SSRF's "can a caller steer the destination?". Flags fixed
  destinations outside `--egress-allowlist` (`MCP040`, MEDIUM), unbounded caller-controlled
  targets (`MCP041`, HIGH), and a **trusted-destination residual** (`MCP042`, LOW/MEDIUM) for
  an allowlisted host that is multi-tenant or credential-bearing — the January 2026 Claude
  Cowork lesson that a trusted host is not automatically a safe destination. Static and
  schema/URI-derived; reuses the SSRF host primitives; never issues a request or reads a
  credential value. Gated in policy via the dedicated `fail_on.egress` key, with
  `egress_allowlist` / `multi_tenant_hosts` policy config that merges with the CLI flags.
  A per-server `servers.<name>.egress_allowlist` unions extra trusted destinations onto the
  global allowlist for that server only (mirroring per-server `denied_permissions`).
  `--egress-check` runs SSRF internally to map outbound destinations; those SSRF findings
  are reported only when `--ssrf-check` is also passed.
  Renders in the terminal, HTML, and SARIF reports. See `docs/EGRESS-DETECTION.md` and
  `examples/policies/egress.yaml`.

## [2.0.0] - 2026-06-07

### Changed

- **Distribution rename:** PyPI package is now `mcp-audits` (was `mcp-permission-audit`).
  The CLI command (`mcp-audit`), import package (`mcp_audit`), and all behavior are
  unchanged. Existing installs of `mcp-permission-audit` continue to work; future
  releases will only publish to `mcp-audits`. Update your install path:
  `uv tool install mcp-audits` / `pip install mcp-audits`.

## [1.13.1] - 2026-06-07

### Changed

- Refreshed the published package metadata/docs so PyPI shows the canonical
  external field-report command with `--redact`:
  `mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact`.
  No scanner behavior or output contract changes.

## [1.13.0] - 2026-06-06

### Added

- Added opt-in **field-report redaction** (`scan --redact`). On top of the always-on
  credential-value redaction, it scrubs the machine hostname and home-directory usernames
  (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`) from `--json`, `--sarif`, and `--html`
  output, so a config-only field report is safe to share publicly. Path *shape* is preserved
  (only the identifying segment is replaced); terminal output keeps real values for local
  readability. Server names are replaced with stable per-report aliases (`server-01`, …)
  everywhere they appear — structured fields, free-text summaries, and command basenames; the
  field-report redaction checklist remains the backstop for any residual free-text specifics.

## [1.12.0] - 2026-06-02

### Added

- Added opt-in, network-gated **byte-level artifact verification** (`scan --download-artifacts`,
  rule `MCP026`). Where `MCP025` compares the registry's *published* hash, this downloads the
  actual bytes the registry serves, hashes them, and checks them against both the registry's
  own published hash and a byte-hash captured at pin time:
  - `PUBLISHED_MISMATCH` (HIGH) — served bytes do not match the registry's own published hash:
    a CDN, mirror, or man-in-the-middle serving content inconsistent with the registry's
    integrity metadata (a content-level signal `MCP025` cannot see).
  - `BASELINE_MISMATCH` (HIGH) — a file pinned at baseline now serves different bytes or has
    vanished (republish-in-place / tampering, proven at the byte level). Verification is
    per distribution file, so a *newly added* file on a frozen version (e.g. a late wheel
    upload) is reported as an advisory **MEDIUM** rather than a false HIGH — and is never
    silently ignored.
  - `UNVERIFIED` (MEDIUM) — bytes could not be downloaded or hashed (unreachable, withdrawn,
    over the size/file-count cap, or a download host not on the registry/CDN allowlist).

  Pin-time capture verifies bytes against the published hash *before* baselining and refuses
  (with a warning, surfaced in `pin --refresh --json` as `artifact_warnings`) to baseline bytes
  that disagree — never trusting poisoned bytes. Downloads stream through bounded hashers
  (64 MiB/file, 24-file cap), never to disk, and only to an allowlist of registry/CDN hosts
  re-validated on every redirect hop (SSRF guard). npm consistency is verified against whichever
  SRI algorithm the registry actually published (sha256/384/512). Network is contacted **only**
  under `--download-artifacts` (on both `pin` to capture the baseline and `scan` to compare).
  Added `fail_on.artifact_verify` policy gate, SARIF rule `MCP026`, terminal + HTML report
  sections, and a `get_artifact_verify_findings` MCP server tool.

### Changed

- When both `--verify-artifacts` and `--download-artifacts` run, a package's registry metadata
  JSON (which carries both the published hash and the artifact download URL) is now fetched once
  per scan via a shared, lock-guarded client cache instead of once per check.

## [1.11.0] - 2026-05-31

### Added

- Added opt-in, network-gated registry package verification (`scan --verify-artifacts`,
  rule `MCP025`). For package-runner launches (`npx pkg@x` / `uvx pkg`) the meaningful
  artifact is the remote package, not the on-disk runner; this compares the
  **registry-published hash** (npm `dist.integrity`, PyPI per-file sha256s) for the
  exact pinned `package@version` against the hash captured at pin time. A changed
  published hash for a fixed version is HIGH (republish-in-place / tampering — a
  registry must never serve different bytes for the same version); an unverifiable
  fetch is MEDIUM. Network is contacted **only** under `--verify-artifacts` (on both
  `pin` to capture the baseline and `scan` to compare); a version *float* is deferred
  to provenance (MCP021). Covers npm + PyPI. Added `fail_on.package_verify` policy
  gate, SARIF rule MCP025, terminal + HTML report sections, a `get_package_verify_findings`
  MCP server tool, and `docs/PACKAGE-VERIFICATION.md` + `examples/policies/package-verify-ci.yaml`.
- Added an opt-in SSRF host allowlist (`scan --ssrf-allowlist host1,host2`). When
  supplied, it suppresses SSRF findings whose **fixed, non-templated** target host
  is allowlisted (subdomains included) — e.g. a resource `https://api.trusted.com/{id}`.
  Findings with a caller-controlled target (templated host, or a tool URL/host
  param) are **never** suppressed, since the allowlist cannot constrain them. The
  default (no allowlist) is a no-op; this is user-driven ground truth and does not
  change the scorer or any default severity. The number suppressed is reported.

### Changed

- `scan --provenance-check` / `--integrity-check` now emit a per-server warning
  when a scanned server is pinned but its baseline predates launch-config /
  artifact-hash capture (previously those servers were silently skipped). The
  message names the servers and points to `mcp-audit pin` to re-capture.

## [1.10.0] - 2026-05-31

### Added

- Added optional launch-artifact integrity detection (`scan --integrity-check`).
  It hashes the on-disk artifact a server launches — the resolved command binary
  and any local script passed as an argument — and flags drift vs the pin
  baseline: `MCP024` (HIGH) when the SHA-256 changed, MEDIUM when the pinned file
  is gone from its path. The launch command string can stay byte-identical while
  the file it points at is swapped underneath you, so this catches a supply-chain
  substitution that the schema and provenance (config-string) checks cannot see.
  Offline and deterministic — only local bytes are hashed (capped at 64 MiB per
  file); nothing is fetched. The pin baseline now snapshots artifact hashes;
  `--integrity-check` implies a pin comparison and baselines pinned before this
  release are skipped until re-pinned. Package-runner launches (`npx`/`uvx`) hash
  the runner binary, not the remote package — registry-artifact verification is a
  separate, network-gated follow-up. Added `fail_on.integrity` policy gate, SARIF
  rule MCP024 (category `integrity`), a terminal report section, a
  `get_integrity_findings` MCP server tool, and `docs/INTEGRITY-DETECTION.md` +
  `examples/policies/integrity-aware-ci.yaml`.
- `pin --refresh <server>` now surfaces capability-escalation (`MCP018`/`MCP019`)
  and launch-config/provenance (`MCP020`–`MCP023`) deltas vs the pin baseline in
  the same review, alongside schema drift — shown **unconditionally** (no
  `--escalation-check` / `--provenance-check` needed), since a refresh is the
  review-before-bless moment where a rug-pull or launch swap must not slip
  through. Both the terminal review and `--json` output gain `escalation` and
  `provenance` sections.

## [1.9.0] - 2026-05-31

### Added

- Added a composite **GitHub Action** (`action.yml` at the repo root, usable as
  `uses: saagpatel/MCPAudit@v1.9.0`) so CI adoption is a single step instead of a
  hand-assembled install + scan + upload workflow. It runs config-only by default
  (`skip-connect: "true"`), writes SARIF, and uploads it to GitHub code scanning
  when `upload-sarif` is `true`. A failing `policy` exits `2` *after* the report is
  written and SARIF is uploaded, so the gate is enforced without losing artifacts.
  Inputs (`version`, `args`, `skip-connect`, `clients`, `config`, `policy`, `sarif`,
  `json`, `upload-sarif`, `working-directory`) are passed to the command via
  environment variables — never interpolated into the shell — so crafted input
  values cannot inject commands. Outputs: `sarif-file`, `json-file`, `exit-code`.
- Added a **pre-commit hook** (`.pre-commit-hooks.yaml`, `id: mcp-audit`) that audits
  repo-local MCP configs on commit, config-only (never spawns or connects). It
  triggers when a repo-root `.mcp.json` or a `.vscode/mcp.json` changes.
- Claude Code discovery now also reads a repo-root `.mcp.json` (Claude Code's
  project-shared config, top-level `mcpServers`) relative to the current working
  directory, so repo-local servers are audited in CI and pre-commit runs. Absent
  files are skipped, so this is a no-op outside a repo that commits `.mcp.json`.
- Added a `Self Audit` workflow that dogfoods the composite action (`uses: ./`) on
  every push, exercising the published install -> scan -> SARIF -> upload contract.

### Fixed

- `scan` now writes requested `--json` / `--sarif` / `--html` report files even
  when no MCP servers are discovered (previously it returned early and wrote
  nothing). CI consumers such as SARIF upload always receive a valid artifact.

## [1.8.0] - 2026-05-31

### Added

- Added optional launch-config / provenance drift detection (`scan --provenance-check`)
  that compares a server's launch configuration against its pin baseline and flags
  supply-chain changes the tool-schema check cannot see — a server can keep identical
  tool schemas while repointing `npx pkg@1.2.3` to `@latest`, swapping its binary,
  gaining `--no-sandbox`, or changing its HTTP endpoint. Four rule kinds:
  - **MCP020 (command)** — command/binary or transport changed (HIGH).
  - **MCP021 (args)** — launch arguments changed (version float, package swap, new flag);
    MEDIUM, or HIGH if a known-dangerous flag (`--no-sandbox`, `--dangerously-*`, …) was gained.
  - **MCP022 (url)** — HTTP endpoint/URL changed (HIGH).
  - **MCP023 (credentials)** — declared env/header KEY-NAME set changed (MEDIUM).
  The pin baseline now snapshots the launch config (command, args, url, transport, and
  env/header **key names only — never values**). `--provenance-check` implies a pin
  comparison; baselines pinned before this release are skipped until re-pinned. Findings
  are a pure delta, so an unchanged launch config produces nothing. Added
  `fail_on.provenance` policy gate, SARIF rules MCP020–MCP023 (category `provenance`),
  a terminal report section, a `get_provenance_findings` MCP server tool, and
  `docs/PROVENANCE-DETECTION.md` + `examples/policies/provenance-aware-ci.yaml`.
- Added a single-file HTML report output (`scan --html PATH`) alongside the
  existing terminal/JSON/SARIF formats. The report is self-contained (inline CSS,
  no JavaScript, no external resources) so it renders offline and can be shared
  as-is. It surfaces every finding type (permissions, prompt-injection, SSRF,
  trifecta, escalation, drift, fleet shadowing, config health, policy result).
  Built from a redacted report copy, and every dynamic value is HTML-escaped so
  an attacker-influenceable tool description can never turn the report into an
  XSS vector.
- Added optional capability-escalation ("rug pull") detection (`scan --escalation-check`)
  that compares each tool against its operator-blessed pin baseline and flags
  security-significant escalations over time. Two rule kinds:
  - **MCP018 (capability)** — a pinned tool GAINED a dangerous permission category it
    did not hold when pinned. HIGH when the gained category is
    `exfiltration`/`shell_execution`/`destructive`; MEDIUM for `file_write`/`network`.
  - **MCP019 (description-injection)** — a pinned tool's description GAINED
    prompt-injection pattern(s) absent from the baseline.
- `--escalation-check` implies a pin comparison: it reuses the pin store as the
  baseline (run `mcp-audit pin` first). Findings are a pure delta against the
  baseline — a tool matching its pin produces nothing, so findings stay scoped to
  reviewed baseline deltas. The check reuses the existing permission and
  injection analyzers; no new inference is performed and no network request is made.
- Added `fail_on.escalation` policy gate, SARIF rules MCP018/MCP019
  (category `capability_escalation`), a terminal "Capability Escalation" report
  section, and a `get_escalation_findings` MCP server tool.
- Drift output stays gated on `--pin-check`; `--escalation-check` alone emits only
  escalation findings.
- New docs: `docs/ESCALATION-DETECTION.md` and
  `examples/policies/escalation-aware-ci.yaml`.

## [1.7.0] - 2026-05-31

### Added

- Added optional lethal-trifecta / toxic-flow detection (`scan --trifecta-check`)
  that identifies when MCP servers cover the canonical agent-exfiltration attack
  surface with three calibrated legs: (1) sensitive data access (`file_read`
  permission), (2) untrusted-content ingestion (SSRF-detector-flagged tool/resource
  OR a tool name/description carrying a fetch verb — NOT the broad `network`
  category, which fires on ~86% of servers and is non-discriminating), and (3)
  exfiltration capability (`exfiltration` permission only — `shell_execution` and
  `file_write` alone do not enable exfiltration and are excluded). The check is
  static and inference-derived: it re-uses findings already computed by the scanner
  and never issues network requests or reads credential values.
- Two finding tiers: per-server (HIGH, `MCP013`) when a single server covers all
  three legs, and fleet-level advisory (MEDIUM, `MCP014`) when the trifecta is
  only assembled by combining multiple servers. Fleet findings are non-redundant:
  suppressed whenever any per-server finding fires.
- Added `ServerAudit.trifecta_findings` (per-server, list) and
  `AuditReport.fleet_trifecta_findings` (fleet-level, top-level list) to the JSON
  output. Both fields default to empty and are only populated with
  `--trifecta-check`.
- Added stable SARIF rule IDs `MCP013` (per-server HIGH) and `MCP014` (fleet
  advisory MEDIUM), a trifecta terminal section, a `get_trifecta_findings` MCP
  server tool, a trifecta report fixture, unit and integration test coverage, and
  `docs/TRIFECTA-DETECTION.md`.
- Added a dedicated `fail_on.trifecta` policy gate (opt-in; not covered by the
  broad `fail_on.severity` shortcut, so existing policy files keep their previous
  behavior). See `examples/policies/trifecta-aware-ci.yaml`.
- This is a minor version bump candidate (`1.7.0`) — all changes are additive and
  backward-compatible.
- Added optional cross-server tool-name shadowing detection (`scan --shadow-check`)
  that flags when two or more configured MCP servers expose tools with colliding or
  confusable names — a vector for tricking an AI agent into routing a call to the
  wrong (possibly malicious) server. Three tiers: exact-name collision (HIGH,
  `MCP015`), normalised collision after case-fold and separator strip (MEDIUM,
  `MCP016`), and homoglyph collision where non-ASCII confusable codepoints spoof an
  ASCII tool name (HIGH, `MCP017`). The detector is fleet-level only (tool names are
  unique within a single server by the MCP spec), offline, and deterministic — no
  network requests, no new runtime dependencies, no credential-value reads.
- In a 21-server real-world corpus there are zero exact or normalised collisions
  (legit servers namespace their tools). Exact-match HIGH findings are designed
  to stay low-noise because the detector avoids fuzzy matching and reports only
  concrete cross-server collisions.
- Added `AuditReport.shadowing_findings` (top-level list, populated only with
  `--shadow-check`; defaults to empty so all existing consumers are unaffected),
  stable SARIF rule IDs MCP015/016/017, a shadowing terminal section, a
  `get_shadowing_findings` MCP server tool, a shadowing report fixture, unit and
  integration test coverage, and `docs/SHADOWING-DETECTION.md`.
- Added a dedicated `fail_on.shadowing` policy gate (opt-in; not covered by the
  broad `fail_on.severity` shortcut). See `examples/policies/shadowing-aware-ci.yaml`.

## [1.6.0] - 2026-05-30

### Added

- Added optional SSRF detection (`scan --ssrf-check`) that flags MCP tools and
  resources whose interface lets a caller steer a server-side request target —
  URL/host parameters paired with fetch verbs, and caller-templated remote
  resource hosts. The check is static and schema-derived: it never issues a
  network request and never reads a credential value.
- Added stable SARIF rule IDs `MCP011` (high) and `MCP012` (medium/low), an
  additive `ssrf_findings` list on each `ServerAudit`, an SSRF terminal section,
  a `get_ssrf_findings` MCP server tool, an SSRF report fixture, integration
  coverage, and `docs/SSRF-DETECTION.md`.
- Added a dedicated `fail_on.ssrf` policy gate (opt-in; not covered by the broad
  `fail_on.severity` shortcut, so existing policy files keep their behavior).
- Extended SSRF resource detection to non-web remote schemes (git, s3, gs, az,
  azure, mongodb, mysql, postgres, redis), aligned with the resource permission
  analyzer, so a caller-templated database/cache/bucket/git host is flagged like
  a templated web host. Added the `ssrf-aware-ci.yaml` example policy.

## [1.5.5] - 2026-05-10

### Added

- Added an external field-report request packet with copy-paste contributor
  instructions, redaction guidance, and maintainer triage steps.
- Added tests that keep the request packet linked from public docs and aligned
  with the external evidence issues.

### Changed

- Refreshed field-report, roadmap, beta-readiness, feedback, README, and release
  metadata for the `1.5.5` outreach polish lane.

## [1.5.4] - 2026-05-10

### Added

- Added the external field-evidence milestone and issue links to beta-readiness,
  field-report, roadmap, feedback, and README docs.
- Added tests that keep the external field-evidence milestone and issue links
  visible in public docs.

### Changed

- Refreshed release metadata for the `1.5.4` coordination polish lane.

## [1.5.3] - 2026-05-10

### Added

- Added a dedicated public field-report issue template for config-only external
  beta-readiness evidence.
- Added tests that keep field-report intake docs, templates, and beta-readiness
  notes aligned.

### Changed

- Expanded field-report and feedback-to-fixtures docs with the external intake
  path, fixture acceptance bar, and beta blocker.
- Refreshed beta-readiness and roadmap docs for the `1.5.3` polish lane.

## [1.5.2] - 2026-05-10

### Added

- Added consumer-contract tests that exercise Python, Node, and dashboard
  examples against compatibility and field-report fixtures.
- Added redacted field-report fixtures for mixed, single-client, and quiet
  config-only setup shapes.
- Added field-report evidence docs and release decision notes.

### Changed

- Refreshed roadmap and beta-readiness evidence docs for the `1.5.2` polish
  lane.

## [1.5.1] - 2026-05-10

### Added

- Added output-contract upgrade compatibility fixtures for older report shapes
  and additive future fields.
- Added beta-readiness evidence notes from config-only, non-spawning scans of
  real local MCP setup shapes.

### Changed

- Refreshed beta, stable, output-contract, and roadmap docs for the `1.5.x`
  readiness state.

## [1.5.0] - 2026-05-10

### Added

- Added adoption smoke coverage for docs, CI examples, report artifacts, and
  `1.5` milestone tracking.
- Added redacted config-health fixtures for local shadowing, remote credential
  headers, and shell-wrapped remote arguments.
- Added prompt/resource scoring validation cases for issue tracker, browser
  automation, and resource-injection metadata.
- Added a `1.5` release decision note documenting why this line ships as
  adoption hardening instead of beta.

### Changed

- Updated the composite scoring proposal with the latest fixture evidence while
  keeping `risk_score.composite` unchanged.

## [1.4.3] - 2026-05-10

### Added

- Added `mcp-audit pin --clear-stale` for dry-run bulk stale pin cleanup, with
  `--apply` required before removing baselines.
- Added a documented combined-score proposal for future prompt/resource scoring
  migration without changing `risk_score.composite`.

### Changed

- Expanded the dashboard JSON consumer summary with status counts, max risk
  values, policy failure count, and attention rows.

## [1.4.2] - 2026-05-10

### Added

- Added calendar, container registry, and vault-style prompt/resource
  calibration cases plus an additional benign glossary case.
- Added a dashboard status-page style report fixture for JSON consumer examples.

### Changed

- Updated roadmap and feedback guidance to reflect the current `1.4.2` project
  state and the fixture evidence still needed before scoring changes.

## [1.4.1] - 2026-05-10

### Added

- Added GitHub, PostgreSQL, and Slack-style prompt/resource calibration cases
  for `non_tool_risk` fixture depth.
- Added a dashboard-oriented JSON consumer example for CI summaries.

### Changed

- Clarified remediation guidance for intentional project-local server shadowing
  before pinning.

## [1.4.0] - 2026-05-10

### Added

- Added config-health diagnostics for missing local stdio command paths and
  server names that conflict across global and project scopes.
- Added config-health diagnostics for package-runner source review and duplicate
  server names that point at different commands or URLs.
- Added a GitHub Actions example for `fail_on.config_health` and expanded JSON
  consumer examples with config-health severity summaries.
- Added `docs/ROADMAP-NEXT.md` for the post-`1.3.0` roadmap.

## [1.3.0] - 2026-05-10

### Added

- Added optional `fail_on.config_health` policy gates, including per-server
  overrides, for structured config-health findings.

## [1.2.0] - 2026-05-10

### Added

- Added structured `config_health_findings` to JSON reports for duplicate server
  names, missing stdio commands, deprecated SSE transports, shell-wrapper
  launches, remote endpoints, remote URL arguments, and credential-heavy
  configs.

## [1.1.4] - 2026-05-10

### Added

- Added config-health warnings to `discover` and `scan` so duplicate names,
  missing stdio commands, deprecated SSE transports, shell-wrapper launches,
  remote endpoints, and credential-heavy configs are visible before pinning or
  connected scans.

## [1.1.3] - 2026-05-10

### Added

- Added a golden rollout guide for staged MCPAudit adoption from config-only
  review through policy gates.
- Added a Qdrant-style vector database validation fixture for semantic-search
  storage and lookup calibration.

### Fixed

- Prevented ambiguous pin and pin refresh writes when multiple discovered MCP
  configs share the same server name.

## [1.1.2] - 2026-05-10

### Added

- Added CI and workstation examples for read-only stale pin review.
- Added fixture-ready feedback guidance so public reports can become safer,
  smaller regression tests.

## [1.1.1] - 2026-05-10

### Added

- Added `1.1` adoption notes with JSON parsing examples for `non_tool_risk`.
- Added a generated JSON Schema artifact for output consumers.
- Added policy-pack guidance that maps example policies to adoption scenarios.
- Added Python and Node JSON consumer examples for compact report summaries.
- Added non-tool calibration cases for prompt/resource capability and injection
  signals.
- Added `mcp-audit pin --stale` for read-only review of pinned servers that are
  no longer present in discovered MCP configs.

## [1.1.0] - 2026-05-09

### Added

- Added additive `non_tool_risk` scoring for prompt and resource capability or
  injection findings without changing `risk_score.composite`.
- Added terminal and JSON coverage for the non-tool risk signal.
- Added regression coverage for LLM confidence scoring, non-tool scoring, and
  output-contract compatibility.
- Added CI workflow examples for GitHub SARIF upload and JSON policy gates.
- Added a browser-automation CI policy profile for reviewed Playwright and
  Puppeteer-style MCP servers.
- Added Notion, Linear, and Atlassian validation fixtures to expand the
  real-world server corpus.
- Added a `1.1` roadmap for additive post-stable product depth.

### Changed

- Bumped the package to `1.1.0` for the first stable minor feature release.
- Refined stable output-contract wording for compatible `1.x` additive fields.
- Linked feedback, adoption, and roadmap docs to the new stable-era examples.

## [1.0.0] - 2026-05-09

### Changed

- Promoted MCPAudit from release candidate to stable `1.0.0`.
- Made whole-repo strict typing (`uv run mypy .`) the canonical type gate after
  repairing test and fixture typing debt.
- Refreshed release, roadmap, security, and readiness docs so stable public
  claims match live CLI behavior and published package metadata.

## [1.0.0rc1] - 2026-05-09

### Changed

- Promoted the package to the first `1.0.0` release candidate.
- Refreshed `CLAUDE.md`, SECURITY, beta readiness, stable readiness, and release
  checklist docs against live CLI behavior and packaging metadata.
- Added `scan --config-only` for isolated audits of a single explicit config
  file without also scanning locally discovered MCP client configs.
- Recorded the stable scoring decision: prompt/resource findings remain
  reportable and policy-gatable, but outside `risk_score.composite` for
  `1.0.0`.

## [1.0.0b3] - 2026-05-09

### Added

- Added stable-readiness documentation with the go/no-go bar for `1.0.0`.
- Added a prompt/resource scoring migration proposal that keeps composite risk
  stable while defining an additive `non_tool_risk` path.
- Added beta-feedback-to-fixtures guidance so false positives, false negatives,
  policy gaps, and output-shape issues become regression tests.
- Added stricter reviewed-workstation and approved-server-only CI policy
  examples.
- Added golden output-contract snapshot coverage for representative JSON and
  SARIF report shapes.

### Changed

- Refreshed README, roadmap, beta readiness, output contract, adoption, and
  security-review docs for the stable-readiness lane.

## [1.0.0b2] - 2026-05-09

### Added

- Added an adoption guide with local review, team CI, GitHub code scanning, and
  pin-baseline workflows.
- Added beta security review notes covering config discovery, connected scan
  boundaries, redaction, AI-output handling, and LLM-mode risks.
- Added a beta feedback issue template for false positives, missing detections,
  SARIF/JSON feedback, policy requests, and pinning workflow friction.
- Expanded the real-world validation corpus with AWS S3, Docker, email, Google
  Drive, and Kubernetes server shapes.
- Added prompt/resource calibration tests for remote resource schemes and risky
  prompt arguments.
- Added pin lifecycle regression tests for intentionally cleared servers and
  renamed tools.

### Changed

- Added tool target metadata to JSON/SARIF permission and drift findings for
  consistency with prompt/resource findings.
- Classified common remote resource URI schemes such as `s3://`,
  `postgres://`, `github://`, and `ws://` as network capabilities.
- Clarified output-contract compatibility rules and the prompt/resource scoring
  calibration bar.

## [1.0.0b1] - 2026-05-09

### Added

- Added beta readiness documentation with the release bar, current limitations,
  and verifier checklist.
- Added dedicated pin maintenance guidance for reviewed refreshes and
  intentionally removed servers.
- Added a prompt/resource scoring boundary note that documents why non-tool
  findings are reportable and policy-gatable but do not yet affect composite
  risk.
- Added the real-world MCP server validation corpus to the pytest suite.

### Changed

- Bumped package metadata from alpha to beta.
- Updated CLI help, README, roadmap, and SECURITY wording to match prompt and
  resource injection analysis.

## [1.0.0a6] - 2026-05-09

### Added

- Extended `--inject-check` to inspect prompt and resource text in addition to
  tool names and descriptions.
- Added target metadata to injection findings so JSON and SARIF identify
  whether a finding came from a tool, prompt, or resource.
- Added policy gates for required pin coverage, separate permission/injection/
  capability thresholds, and per-server threshold overrides.
- Added `mcp-audit pin --refresh <server> --json` for automation-friendly
  refresh review output.
- Added CI examples and additional output-contract fixtures for failed,
  config-only, policy, and prompt/resource report shapes.

### Changed

- Improved resource capability classification with parsed URI scheme, host,
  path, and template-variable signals.
- Refreshed README, roadmap, SECURITY, output contract, and policy examples for
  the richer prompt/resource and policy behavior.

## [1.0.0a5] - 2026-05-09

### Added

- Added `mcp-audit pin --refresh <server>` as a dry-run review for one server's
  pin drift before rotating its baseline.
- Added `mcp-audit pin --refresh <server> --apply` to refresh a reviewed
  server baseline explicitly.

### Changed

- Updated pin workflow docs so expected MCP server upgrades can be reviewed
  before any pin file writes happen.

## [1.0.0a4] - 2026-05-09

### Added

- Expanded `mcp-audit pin --status` into a baseline review command with server
  counts, total pinned tools, pin ages, and `--json` output.
- Added a release checklist covering verifier, build, publish, and clean-install
  smoke checks.

### Changed

- Refreshed README, SECURITY, and roadmap release notes for the published
  `mcp-permission-audit` alpha.

## [1.0.0a3] - 2026-05-09

### Fixed

- Added the documented `mcp-audit --version` command and aligned package
  version reporting with the renamed PyPI distribution.

## [1.0.0a2] - 2026-05-09

### Changed

- Renamed the PyPI distribution to `mcp-permission-audit` after the
  `mcp-audit` project name was found to be unavailable on PyPI.
- Kept the installed CLI command as `mcp-audit` to preserve user workflows,
  examples, MCP server config entries, and pin-file paths.

### Added
- Prompt and resource inventory now produces permission findings for risky
  arguments, URI schemes, and metadata, with terminal, JSON, SARIF, and policy
  gate coverage.
- Policy gates now support server allowlists, per-server risk limits,
  per-server denied permissions, and starter policy examples.
- SARIF output now includes tool schema drift and policy gate violations, backed
  by a documented output contract and compatibility fixture.

## [1.0.0a1] - 2026-05-09

First public alpha. Behavior and public CLI surface are stable enough to audit
real workstations; API surface may still shift before the `1.0.0` stable cut.

### Added
- Permission and prompt-injection findings now carry stable rule metadata:
  rule IDs, severity, title, description, and suggested remediation in JSON,
  with richer SARIF rule metadata and stable fingerprints.
- Added a shared redaction layer for terminal, JSON, SARIF, and connection
  error output so likely credential values are masked consistently.
- `scan --skip-connect` now performs deeper config-only risk inference for
  declared HTTP/SSE endpoints, shell wrappers, package runners, remote URLs,
  destructive shell patterns, and credential-like env key names.
- Tool schema drift findings now include plain-language summaries, changed
  field hints, and suggested remediation in terminal and JSON reports.
- `scan --policy` evaluates local YAML policy gates for severity thresholds,
  denied permission categories, drift findings, and max server risk.
- Connected scans now inventory MCP prompts and resources in addition to tools,
  with JSON and terminal counts for broader server capability coverage.

### Fixed
- `mcp-audit pin` now connects to MCP servers before writing schema pins, so
  drift baselines contain real tool schemas instead of empty skip-connect scans.
- The MCP server `get_injection_findings` tool now runs a connected scan with
  injection checks enabled before returning findings.
- Removed the case-conflicting duplicate pull request template from `.github/`.

### Changed
- README, SECURITY, and CONTRIBUTING now make first-run and verification
  expectations clearer: `discover` is the safest first command, `--skip-connect`
  is the config-only scan mode, `pin` intentionally connects to servers, and the
  canonical verifier is `uv run pytest`, `uv run ruff check`, `uv run mypy src`.
- Pin files now keep reviewable tool metadata snapshots next to the SHA256 hash
  so drift reports can identify description and input-schema changes.
- IMPLEMENTATION-ROADMAP now reflects the current codebase, trust boundaries,
  verification contract, and post-Phase-1 expansion priorities.
- CI now runs on common maintenance branch prefixes, including `codex/**`.
- Updated security and project notes to state the current scan trust boundary:
  standard scans enumerate live MCP tool metadata, while `--skip-connect` is the
  config-only mode.

### Security
- Locked dependency upgrades for the alpha release:
  `cryptography` → 46.0.7 (buffer overflow on non-contiguous buffers,
  GHSA-p423-j2cm-9vmq), `pytest` → 9.0.3 (vulnerable tmpdir handling,
  GHSA-6w46-j5rx-g56g), `python-multipart` → 0.0.26 (DoS via large
  multipart preamble/epilogue, GHSA-mj87-hwqh-73pj), `python-multipart`
  → 0.0.27 (multipart header limits), and `pygments` → 2.20.0 (ReDoS in
  GUID matching, GHSA-5239-wwwm-4pmq).

### Changed
- README: corrected feature and CLI claims to match v0.3 code — permission
  categories listed as the actual six (`file_read`, `file_write`, `network`,
  `shell_execution`, `destructive`, `exfiltration`); risk-score description
  replaced with the real per-category weighted-sum formula; drift workflow
  documented via `mcp-audit pin` / `scan --pin-check` (replacing the
  `baseline save`/`diff` shorthand); client list expanded to include VSCode
  and Windsurf; scan filter flag corrected to `--clients`; pin storage path
  corrected to `~/.mcp-audit-pins.yaml`; MCP SDK floor bumped to `1.27+`;
  SARIF 2.1.0, `--inject-check`, `--llm-analysis`, and `mcp-audit[watch]`
  extra added to the usage examples.

## [0.3.0] - 2025-01-01

### Added
- Watch mode (`--watch`) for continuous re-auditing via `watchfiles`
- Optional LLM-assisted permission classification via `anthropic` optional dependency (`--llm-analysis`)
- Schema drift detection across MCP server capability declarations through `mcp-audit pin` and `scan --pin-check`
- SARIF 2.1.0 export support
- Support for Python 3.13

### Changed
- Improved prompt injection scoring to detect multi-turn injection patterns
- Risk score breakdown now includes per-dimension contribution weights

### Fixed
- JSON5 config parsing for Claude Desktop configs with trailing commas
- Connector timeout handling on slow MCP server startup

## [0.2.0] - 2024-11-01

### Added
- Prompt injection threat analysis across tool names and descriptions
- Permission risk scoring
- Rich terminal output with color-coded risk levels
- JSON output for CI pipeline integration
- Support for Cursor, Windsurf, and VS Code MCP config locations

### Changed
- Redesigned CLI using Click for composable subcommands
- Risk scoring model updated to weight filesystem and shell access higher

### Fixed
- Config discovery on Windows paths with spaces
- Graceful degradation when an MCP server binary is not found

## [0.1.0] - 2024-09-15

### Added
- Initial release
- MCP config discovery for Claude Desktop (`claude_desktop_config.json`)
- Permission enumeration: filesystem paths, environment variable exposure, network access
- Risk score output with pass/warn/fail thresholds
- `mcp-audit` CLI entry point

[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/saagpatel/MCPAudit/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/saagpatel/MCPAudit/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/saagpatel/MCPAudit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/saagpatel/MCPAudit/compare/v1.13.1...v2.0.0
[1.13.1]: https://github.com/saagpatel/MCPAudit/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/saagpatel/MCPAudit/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/saagpatel/MCPAudit/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/saagpatel/MCPAudit/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/saagpatel/MCPAudit/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/saagpatel/MCPAudit/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/saagpatel/MCPAudit/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/saagpatel/MCPAudit/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/saagpatel/MCPAudit/compare/v1.5.5...v1.6.0
[1.5.5]: https://github.com/saagpatel/MCPAudit/compare/v1.5.4...v1.5.5
[1.5.4]: https://github.com/saagpatel/MCPAudit/compare/v1.5.3...v1.5.4
[1.5.3]: https://github.com/saagpatel/MCPAudit/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/saagpatel/MCPAudit/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/saagpatel/MCPAudit/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/saagpatel/MCPAudit/compare/v1.4.3...v1.5.0
[1.4.3]: https://github.com/saagpatel/MCPAudit/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/saagpatel/MCPAudit/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/saagpatel/MCPAudit/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/saagpatel/MCPAudit/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/saagpatel/MCPAudit/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/saagpatel/MCPAudit/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/saagpatel/MCPAudit/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/saagpatel/MCPAudit/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/saagpatel/MCPAudit/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/saagpatel/MCPAudit/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0rc1...v1.0.0
[1.0.0rc1]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0b3...v1.0.0rc1
[1.0.0b3]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0b2...v1.0.0b3
[1.0.0b2]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0b1...v1.0.0b2
[1.0.0b1]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a6...v1.0.0b1
[1.0.0a6]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a5...v1.0.0a6
[1.0.0a5]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a4...v1.0.0a5
[1.0.0a4]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a3...v1.0.0a4
[1.0.0a3]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a2...v1.0.0a3
[1.0.0a2]: https://github.com/saagpatel/MCPAudit/compare/v1.0.0a1...v1.0.0a2
[1.0.0a1]: https://github.com/saagpatel/MCPAudit/compare/v0.3.0...v1.0.0a1
[0.3.0]: https://github.com/saagpatel/MCPAudit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/saagpatel/MCPAudit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/saagpatel/MCPAudit/releases/tag/v0.1.0
