# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- CI now runs on common maintenance branch prefixes, including `codex/**`.
- Updated security and project notes to state the current scan trust boundary:
  standard scans enumerate live MCP tool metadata, while `--skip-connect` is the
  config-only mode.

### Security
- Locked upgrade for four transitive dependencies flagged by Dependabot:
  `cryptography` → 46.0.7 (buffer overflow on non-contiguous buffers,
  GHSA-p423-j2cm-9vmq), `pytest` → 9.0.3 (vulnerable tmpdir handling,
  GHSA-6w46-j5rx-g56g), `python-multipart` → 0.0.26 (DoS via large
  multipart preamble/epilogue, GHSA-mj87-hwqh-73pj), and `pygments`
  → 2.20.0 (ReDoS in GUID matching, GHSA-5239-wwwm-4pmq).

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

[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/saagpatel/MCPAudit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/saagpatel/MCPAudit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/saagpatel/MCPAudit/releases/tag/v0.1.0
