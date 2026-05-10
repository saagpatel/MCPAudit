# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v1.5.0...HEAD
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
