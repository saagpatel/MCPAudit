# MCP Permission Auditor (mcp-audit)

Python CLI that scans locally configured MCP servers across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. Runs config-only or connected scans; infers permission capabilities, detects prompt-injection patterns, checks pin drift, emits terminal/JSON/SARIF reports. Offline-first by default; networked LLM analysis requires explicit `--llm-analysis`.

## Tech Stack

- Python 3.11+, click 8.x, rich 15.x+, anyio 4.x
- MCP client: official Python SDK; validation: pydantic 2.x
- JSONC: json5 0.10.x; config overrides: pyyaml 6.x
- Testing: pytest 9.x + pytest-anyio; build/package: uv, PyPI (pipx/uvx)

## Dev Conventions

- Type hints everywhere; `mypy --strict` must pass; `ruff` for linting/formatting
- kebab-case filenames, PascalCase classes, snake_case functions
- Conventional commits: feat:, fix:, chore:, docs:
- Unit tests for all analyzers and scorers before committing
- Async by default for server connections; sync wrapper for CLI

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

## Scoped Gates

- **Credentials:** Report env var key names only; never store, log, or transmit values.
- **Config files:** Tool is read-only; never modify any MCP config file.
- **LLM analysis:** Use `--llm-analysis` flag only when operator explicitly requests it.
- **Roadmap labels:** Verify against current code; IMPLEMENTATION-ROADMAP.md phase labels may be stale.
- **Server spawning:** Always guard MCP server process spawns with timeout and cleanup handlers.
- **Config paths:** Resolve via platform-aware path resolution; never hardcode.

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

A Python CLI tool that scans locally configured MCP servers across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. It can run config-only without connecting, or run connected scans that enumerate tools, prompts, and resources with timeout-guarded MCP clients. It infers permission capabilities, detects prompt-injection patterns, checks pin drift, and emits terminal, JSON, and SARIF reports. Default behavior is local-first and deterministic; networked LLM analysis is available only when explicitly requested with `--llm-analysis`.

## Current State

**Stable 1.13.0 maintenance**
The codebase now includes discovery, config-only scans, connected tool/prompt/resource enumeration, permission scoring, prompt-injection checks, SSRF detection, fleet-aware lethal-trifecta and cross-server tool-name shadowing detection, over-time capability-escalation and launch-config/provenance drift detection (vs pin baselines), launch-artifact integrity detection (on-disk hash drift), registry package verification (npm/PyPI published-hash check), byte-level artifact verification (downloaded bytes vs registry and baseline), field-report redaction, schema pinning/drift checks, terminal/JSON/SARIF/HTML output, watch mode, MCP server exposure, overrides, policy gates, and optional LLM-assisted classification. Treat older roadmap phase labels as historical unless they match the current code.

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

# Flag SSRF-prone tools/resources (caller-controlled server-side fetch targets)
mcp-audit scan --ssrf-check
mcp-audit scan --ssrf-check --ssrf-allowlist api.github.com,internal.svc

# Detect lethal-trifecta / toxic-flow attack surface (per-server and fleet-level)
mcp-audit scan --trifecta-check

# Detect cross-server tool-name shadowing (exact, normalised, homoglyph collisions)
mcp-audit scan --shadow-check

# Detect capability escalation ("rug pull") vs the pin baseline
mcp-audit scan --escalation-check

# Detect launch-config / provenance drift vs the pin baseline
mcp-audit scan --provenance-check

# Detect on-disk launch-artifact (binary/script) hash drift vs the pin baseline
mcp-audit scan --integrity-check

# Verify npm/PyPI package@version registry hashes vs the pin baseline (opt-in, network)
mcp-audit pin --verify-artifacts
mcp-audit scan --verify-artifacts

# Download the artifact bytes and verify their hash vs published + baseline (opt-in, network)
mcp-audit pin --download-artifacts
mcp-audit scan --download-artifacts

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

# Export JSON, SARIF 2.1.0, or a self-contained HTML report
mcp-audit scan --json audit.json --sarif audit.sarif
mcp-audit scan --html audit.html

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
