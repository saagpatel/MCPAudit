# MCP Permission Auditor (mcp-audit)

## Overview
A Python CLI tool that scans locally configured MCP servers across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. It can run config-only without connecting, or run connected scans that enumerate tools, prompts, and resources with timeout-guarded MCP clients. It infers permission capabilities, detects prompt-injection patterns, checks pin drift, and emits terminal, JSON, and SARIF reports. Default behavior is local-first and deterministic; networked LLM analysis is available only when explicitly requested with `--llm-analysis`.

## Tech Stack
- Python: 3.11+
- CLI: click 8.x
- Terminal UI: rich 15.x+
- Async: anyio 4.x
- MCP client: mcp (official Python SDK)
- Validation: pydantic 2.x
- JSONC parsing: json5 0.10.x
- Config overrides: pyyaml 6.x
- Testing: pytest 9.x + pytest-anyio
- Build/package: uv, PyPI distribution via pipx/uvx

## Development Conventions
- Type hints everywhere, `mypy --strict` must pass
- `ruff` for linting and formatting
- kebab-case for filenames, PascalCase for classes, snake_case for functions
- Conventional commits: feat:, fix:, chore:, docs:
- Unit tests for all analyzers and scorers before committing
- Async by default for server connections; sync wrapper for CLI

## Current Phase
**Stable 1.0.0 maintenance**
The codebase now includes discovery, config-only scans, connected tool/prompt/resource enumeration, permission scoring, prompt-injection checks, schema pinning/drift checks, SARIF/JSON output, watch mode, MCP server exposure, overrides, policy gates, and optional LLM-assisted classification. Treat older roadmap phase labels as historical unless they match the current code.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Permission inference | Rule-based heuristics only | Offline-first, deterministic, no API keys |
| Transport support | stdio + StreamableHTTP | SSE deprecated per MCP spec |
| Report formats | Rich terminal (default), JSON, SARIF 2.1.0 | Terminal for humans, structured output for CI/CD and SARIF-aware tools |
| Package manager | uv + PyPI | Modern Python tooling, single-command install |
| Async runtime | anyio | Transport-agnostic, works with trio or asyncio |
| Env var handling | Key names only, never values | Security — never log secrets |
| Optional LLM analysis | `--llm-analysis` only | Networked third-party analysis must be explicit |

## Do NOT
- Do not store, log, or transmit any credential values — only report env var key names
- Do not modify any MCP config file — this tool is read-only
- Do not use LLM inference unless the user explicitly requests optional `--llm-analysis`
- Do not treat IMPLEMENTATION-ROADMAP.md phase labels as current truth without checking code
- Do not spawn MCP server processes without timeout guards and cleanup handlers
- Do not hardcode config file paths — use platform-aware path resolution

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

A Python CLI tool that scans locally configured MCP servers across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. It can run config-only without connecting, or run connected scans that enumerate tools, prompts, and resources with timeout-guarded MCP clients. It infers permission capabilities, detects prompt-injection patterns, checks pin drift, and emits terminal, JSON, and SARIF reports. Default behavior is local-first and deterministic; networked LLM analysis is available only when explicitly requested with `--llm-analysis`.

## Current State

**Stable 1.0.0 maintenance**
The codebase now includes discovery, config-only scans, connected tool/prompt/resource enumeration, permission scoring, prompt-injection checks, schema pinning/drift checks, SARIF/JSON output, watch mode, MCP server exposure, overrides, policy gates, and optional LLM-assisted classification. Treat older roadmap phase labels as historical unless they match the current code.

## Stack

- Python: 3.11+
- CLI: click 8.x
- Terminal UI: rich 15.x+
- Async: anyio 4.x
- MCP client: mcp (official Python SDK)
- Validation: pydantic 2.x
- JSONC parsing: json5 0.10.x
- Config overrides: pyyaml 6.x
- Testing: pytest 9.x + pytest-anyio
- Build/package: uv, PyPI distribution via pipx/uvx

## How To Run

```bash
mcp-audit --version

# Discover configured MCP servers without connecting to them
mcp-audit discover

# Scan all configured MCP servers
mcp-audit scan

# Config-only scan that does not spawn or connect to servers
mcp-audit scan --skip-connect

# Filter to specific clients (comma-separated)
mcp-audit scan --clients claude_desktop,cursor

# Scan only one explicit MCP config file
mcp-audit scan --config ./mcp.json --config-only

# Check tools, prompts, and resources for prompt-injection patterns
mcp-audit scan --inject-check

# Pin current tool schemas, then detect drift on later scans.
# Pinning connects to servers so it can capture real tool schemas.
mcp-audit pin
mcp-audit pin --status
mcp-audit pin --status --json
mcp-audit pin --stale
mcp-audit pin --stale --json
mcp-audit scan --pin-check

# Review expected drift for one server before refreshing its baseline.
mcp-audit pin --refresh github
mcp-audit pin --refresh github --json
mcp-audit pin --refresh github --apply

# Export JSON or SARIF 2.1.0
mcp-audit scan --json audit.json --sarif audit.sarif

# Fail CI on local policy violations
mcp-audit scan --policy policy.yaml

# Optional LLM-assisted classification (requires ANTHROPIC_API_KEY)
mcp-audit scan --llm-analysis

# Watch mode — re-scan on config change; use --skip-connect for config-only watching
mcp-audit watch
```

## Known Risks

- Do not store, log, or transmit any credential values — only report env var key names
- Do not modify any MCP config file — this tool is read-only
- Do not use LLM inference unless the user explicitly requests optional `--llm-analysis`
- Do not treat IMPLEMENTATION-ROADMAP.md phase labels as current truth without checking code
- Do not spawn MCP server processes without timeout guards and cleanup handlers
- Do not hardcode config file paths — use platform-aware path resolution

## Next Recommended Move

Maintain the stable scanner and output contracts. For behavior changes, add focused fixtures or sample-scan assertions and update security/output docs when semantics change.

<!-- portfolio-context:end -->
