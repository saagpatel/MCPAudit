# MCP Permission Auditor (mcp-audit)

## Overview
A Python CLI tool that scans all locally configured MCP servers across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf — dynamically connects to each server, enumerates every tool with its annotations and input schema, infers permission capabilities (file access, network, shell execution, destructive writes, exfiltration), and produces a risk-scored audit report. Fully local, offline, zero API keys.

## Tech Stack
- Python: 3.11+
- CLI: click 8.x
- Terminal UI: rich 13.x
- Async: anyio 4.x
- MCP client: mcp (official Python SDK)
- Validation: pydantic 2.x
- JSONC parsing: json5 0.10.x
- Config overrides: pyyaml 6.x
- Testing: pytest 8.x + pytest-anyio
- Build/package: uv, PyPI distribution via pipx/uvx

## Development Conventions
- Type hints everywhere, `mypy --strict` must pass
- `ruff` for linting and formatting
- kebab-case for filenames, PascalCase for classes, snake_case for functions
- Conventional commits: feat:, fix:, chore:, docs:
- Unit tests for all analyzers and scorers before committing
- Async by default for server connections; sync wrapper for CLI

## Current Phase
**Phase 0: Foundation — Config Discovery & Parsing**
See IMPLEMENTATION-ROADMAP.md for full phase details.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Permission inference | Rule-based heuristics only | Offline-first, deterministic, no API keys |
| Transport support | stdio + StreamableHTTP | SSE deprecated per MCP spec |
| Report formats | Rich terminal (default) + JSON | Terminal for humans, JSON for CI/CD |
| Package manager | uv + PyPI | Modern Python tooling, single-command install |
| Async runtime | anyio | Transport-agnostic, works with trio or asyncio |
| Env var handling | Key names only, never values | Security — never log secrets |

## Do NOT
- Do not store, log, or transmit any credential values — only report env var key names
- Do not modify any MCP config file — this tool is read-only
- Do not use LLM inference for permission analysis — heuristics only (for now)
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not spawn MCP server processes without timeout guards and cleanup handlers
- Do not hardcode config file paths — use platform-aware path resolution
