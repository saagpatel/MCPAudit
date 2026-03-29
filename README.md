# mcp-audit

[![Python](https://img.shields.io/badge/Python-3776ab?style=flat-square&logo=python)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> You're giving AI direct access to your computer. Do you actually know what you've installed?

`mcp-audit` gives you x-ray vision into every MCP server configured on your system: what it can do, how risky it is, whether its descriptions are hiding adversarial instructions, and whether it's changed since you last looked. One command, no API keys, fully local.

## Features

- **Permission enumeration** — catalogs every tool's capabilities across `file_read`, `file_write`, `network`, `shell`, `process_spawn`, and 8 other permission categories
- **Risk scoring** — composite 0–10 risk score per server based on permission surface area, tool count, and description anomalies
- **Prompt injection detection** — scans tool descriptions for instruction-override patterns, hidden directives, and adversarial phrasing
- **Schema drift tracking** — compares current tool schemas against a stored baseline; flags additions, removals, and signature changes
- **Multi-client support** — reads configs from Claude Desktop, Claude Code, Cursor, and any custom config path
- **Watch mode** — `mcp-audit watch` re-scans on config file changes via `watchfiles`

## Quick Start

### Prerequisites
- Python 3.11+
- `uv` (recommended) or `pip`

### Installation
```bash
uvx mcp-audit scan
# or install permanently:
uv tool install mcp-audit
```

### Usage
```bash
# Scan all configured MCP servers
mcp-audit scan

# Scan a specific client config
mcp-audit scan --client claude_desktop

# Save a baseline and detect drift later
mcp-audit baseline save
mcp-audit baseline diff

# Watch for config changes
mcp-audit watch
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.11+ |
| CLI | Click 8 |
| Output | Rich |
| MCP protocol | `mcp` SDK 1.0+ |
| Validation | Pydantic v2 |
| Config parsing | PyYAML + json5 |
| Optional LLM | Anthropic SDK |

## Architecture

The scanner enumerates MCP client config files, spawns each server as a subprocess via `anyio`, calls `tools/list` over the MCP protocol, and passes the returned schema to the permission classifier and injection detector. Results are aggregated into a structured report rendered by Rich. The baseline system serializes tool schemas to a local `.mcp-audit/` directory and diffs them on subsequent runs using a canonical hash of each tool signature.

## License

MIT