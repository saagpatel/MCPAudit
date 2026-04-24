# mcp-audit

[![Python](https://img.shields.io/badge/Python-3776ab?style=flat-square&logo=python)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> You're giving AI direct access to your computer. Do you actually know what you've installed?

`mcp-audit` gives you x-ray vision into every MCP server configured on your system: what it can do, how risky it is, whether its descriptions are hiding adversarial instructions, and whether it's changed since you last looked. One command, no API keys, fully local.

## Features

- **Permission enumeration** — catalogs every tool's capabilities across six permission categories: `file_read`, `file_write`, `network`, `shell_execution`, `destructive`, `exfiltration`
- **Risk scoring** — composite 0–10 per server as a weighted sum of per-category max(weight × confidence), with a five-dimension breakdown (file access, network, shell, destructive, exfiltration)
- **Prompt injection detection** — `scan --inject-check` scans tool descriptions for instruction-override patterns, hidden directives, and adversarial phrasing; pattern-based, no LLM required
- **Schema drift tracking** — `mcp-audit pin` snapshots current tool schemas; subsequent `scan --pin-check` flags added, removed, and changed tools via SHA256 hashing with field-level granularity
- **Multi-client support** — reads configs from Claude Desktop, Claude Code, Cursor, VSCode, and Windsurf — plus any custom path via `--config`
- **Structured output** — Rich terminal report plus JSON and SARIF 2.1.0 export for ingestion by GitHub Advanced Security and SARIF-aware SAST pipelines
- **Watch mode** — `mcp-audit watch` re-scans on config file changes via `watchfiles` (optional extra: install with `mcp-audit[watch]`)

## Quick Start

### Prerequisites
- Python 3.11+
- `uv` (recommended) or `pip`

### Installation
```bash
uvx mcp-audit scan
# or install permanently:
uv tool install mcp-audit
# with watch mode support:
uv tool install 'mcp-audit[watch]'
```

### Usage
```bash
# Scan all configured MCP servers
mcp-audit scan

# Filter to specific clients (comma-separated)
mcp-audit scan --clients claude_desktop,cursor

# Check tool descriptions for prompt-injection patterns
mcp-audit scan --inject-check

# Pin current tool schemas, then detect drift on later scans
mcp-audit pin
mcp-audit scan --pin-check

# Export JSON or SARIF 2.1.0
mcp-audit scan --json audit.json --sarif audit.sarif

# Optional LLM-assisted classification (requires ANTHROPIC_API_KEY)
mcp-audit scan --llm-analysis

# Watch mode — re-scan on config change
mcp-audit watch
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.11+ |
| CLI | Click 8 |
| Output | Rich |
| MCP protocol | `mcp` SDK 1.27+ |
| Validation | Pydantic v2 |
| Config parsing | PyYAML + json5 |
| Watch mode | `watchfiles` (optional extra) |
| Optional LLM | Anthropic SDK |

## Architecture

The scanner enumerates MCP client config files, spawns each server as a subprocess via `anyio`, and calls `tools/list` over the MCP protocol. Returned schemas flow into the permission classifier (schema walker + regex ruleset over six permission categories) and the optional injection detector (pattern ruleset for instruction-override, role-switch, and hidden-directive phrasing). The risk scorer composes a per-category weighted sum clamped to 0–10. Reports render via Rich; JSON and SARIF 2.1.0 export are first-class. The pin store serializes SHA256 schema hashes to `~/.mcp-audit-pins.yaml` for drift detection on subsequent `--pin-check` scans.

## License

MIT
