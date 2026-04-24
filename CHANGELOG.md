# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0a1] - 2026-04-24

First public alpha. Version surfaced in all external launch materials (landing page, pitch deck, Product Hunt assets). Behaviour and public CLI surface are considered stable enough to audit real workstations; API surface may still shift before the `1.0.0` stable cut.

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
- LLM-assisted risk narration via `anthropic` optional dependency (`--llm-explain`)
- YAML output format support (`--format yaml`)
- Schema drift detection across MCP server capability declarations
- Support for Python 3.13

### Changed
- Improved prompt injection scoring to detect multi-turn injection patterns
- Risk score breakdown now includes per-dimension contribution weights

### Fixed
- JSON5 config parsing for Claude Desktop configs with trailing commas
- Connector timeout handling on slow MCP server startup

## [0.2.0] - 2024-11-01

### Added
- Prompt injection threat analysis across tool descriptions and resource URIs
- Permission risk scoring with configurable severity thresholds (`--min-severity`)
- Rich terminal output with color-coded risk levels
- JSON output format (`--format json`) for CI pipeline integration
- Support for Cursor, Windsurf, and VS Code MCP config locations
- `--server` flag to audit a single named server in isolation

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
