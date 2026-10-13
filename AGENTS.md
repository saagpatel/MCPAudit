# AGENTS.md

## Purpose

MCPAudit reviews MCP client and server configuration, reports declared access and observed metadata, and highlights drift. Static, read-only review is the default.

## Layout

- `src/mcp_audit/` contains the CLI, discovery, analysis, and report code.
- `tests/` contains unit, integration, and fixture-backed regression tests.
- `docs/` contains user guides, contracts, and maintainer procedures.
- `examples/` contains synthetic configurations and safe walkthroughs.

## Setup

Use Python 3.14.8 and `uv`.

```sh
uv sync --locked --dev
uv run mcp-audit --help
uv run mcp-audit check --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only --skip-connect --override-config /dev/null
```

The explicit fixture, `--config-only`, and empty override keep this smoke test
on synthetic input without discovering workstation configs or connecting.

## Checks

Run `make check` for lint, formatting, type checking, and the default test suite. Use focused pytest commands for targeted changes. Use the synthetic sandbox fixture for CLI smoke checks; connected tests and platform-specific lanes have additional prerequisites documented in `CONTRIBUTING.md`.

## Boundaries

- Prefer explicit synthetic configs with `--config-only --skip-connect` for checks that do not need workstation discovery.
- Do not read `.env` files, keychains, OAuth stores, browser profiles, raw logs, private transcripts, cookies, or credential-bearing configs.
- Reports may contain configuration shape, tool names, and evidence text. Report environment variable key names only, never values, and review output before sharing it.
- Remote package verification, downloads, LLM analysis, and connected scans are opt-in higher-reach operations.
- Preserve report schema compatibility and surface incomplete or skipped checks clearly.

## Delivery

Use small Conventional Commits. Before proposing a release, follow `maintainers/RELEASE-CHECKLIST.md`; do not claim hosted CI, publication, or runtime behavior from local checks alone.
