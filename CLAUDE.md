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
**Release-candidate readiness for 1.0.0**
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
