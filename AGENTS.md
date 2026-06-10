# AGENTS.md

## What This Project Is

`MCPAudit` is a local MCP security and drift audit tool. It inspects MCP client/server configuration and reports what configured servers can reach, with read-only safety as the default operating posture.

## Current State

The repo is an active infrastructure/security project with package metadata, tests, CI, release docs, and a README that emphasizes zero-touch and read-only scan modes.

## Stack

- Python
- `uv`
- pytest
- ruff
- GitHub Actions / CodeQL
- SARIF/JSON/HTML style reporting surfaces

## How To Run

Prefer zero-touch or read-only checks first:

```sh
uv run pytest -q
uv run ruff check .
uv run mcp-audit scan --skip-connect
```

Only run connected scans when the task explicitly calls for live MCP tool-schema inspection and the boundary is clear.

## Known Risks

- MCP config auditing can expose sensitive config shape. Report environment variable key names only, never values.
- Do not read `.env` files, keychains, OAuth stores, browser profiles, raw logs, private transcripts, cookies, or credential-bearing configs.
- Treat remote package verification, downloads, LLM analysis, and connected server scans as higher-reach modes that need explicit justification.

## Next Recommended Move

Keep the release/doctor posture boring: scan safely, verify tests, and make every higher-reach audit mode explicit in command output and docs.
