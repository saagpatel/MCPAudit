# MCPAudit

## Communication Contract

- Follow `/Users/d/.codex/policies/communication/BigPictureReportingV1.md` for all user-facing updates.
- Use exact section labels from `BigPictureReportingV1.md` for formal delivery, blocker, waiting, risk, decision, or explicit status/report requests.
- Keep ordinary in-flight updates conversational, warm, PM-readable, operator-grade, and low-noise.
- Keep technical details in internal artifacts unless explicitly requested by the user or required by failure, risk, or verification.

## Project Goal

MCPAudit is a local MCP permission auditor. Keep it read-only, deterministic, and careful with configured MCP server data. It should enumerate tools, classify permission risk, detect prompt-injection patterns, and report without leaking secrets or mutating MCP configs.

## First Read

- `README.md` for product overview and command examples.
- `CLAUDE.md` for current project notes and scope boundaries.
- `pyproject.toml` for dependency, lint, and typing configuration.
- `tests/` for analyzer, discovery, pinning, SARIF, monitor, and server behavior.

## Core Rules

- Do not store, log, or transmit credential values; env var key names only.
- Do not modify MCP client config files during scans.
- Preserve local/offline deterministic behavior unless a task explicitly asks for optional LLM behavior.
- Keep subprocess/server handling guarded by timeouts and cleanup.
- Keep changes scoped to the current audit, reporting, or verifier task.

## Codex App Usage

- Use Codex App Projects for repo-specific implementation, review, and verification in this checkout.
- Use a Worktree when changing scanner behavior, MCP connection handling, risk scoring, SARIF/JSON output contracts, pinning/drift behavior, or optional LLM classification.
- Use artifacts for reusable security review notes, sample scan reports, release packets, or handoff docs.
- Keep connectors read-first and task-scoped. Do not pull external context unless it directly supports the current MCP/security task.
- Avoid browser or computer use unless reviewing generated documentation or an external client integration that cannot be verified through CLI/tests.

## Verification

- Use `.codex/verify.commands` as the canonical verifier for routine Codex work.
- Current canonical verifier:
  - `uv run pytest`
  - `uv run ruff check`
  - `uv run mypy src`
- Current known follow-up: strict `uv run mypy .` still reports test-only typing debt in fixtures and mocks. Do not call the whole-repo mypy gate green until that backlog is intentionally repaired.
- For behavior changes, add a focused sample scan or fixture assertion when it improves confidence.
- If a command is missing, unclear, or unsafe to run, stop and report the blocker instead of guessing.

## Done Criteria

- The requested change is implemented.
- Relevant tests or checks were run, or the exact reason they were not run is stated.
- Security, output-contract, or operating docs are updated when behavior changes.
- Assumptions, risks, and next steps are summarized before closeout.

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

MCPAudit is a local-first permission and risk auditor for MCP server configurations across tools such as Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf. It inventories configured servers, classifies tool/prompt/resource risk, detects prompt-injection patterns, checks schema drift, and exports human and machine-readable reports without mutating MCP configs.

## Current State

The project is in stable maintenance. Discovery, config-only scans, connected enumeration, permission scoring, prompt/resource scoring boundaries, pinning/drift checks, policy gates, JSON/SARIF output, watch mode, MCP server exposure, and optional LLM classification are all present. Treat old roadmap phase labels as historical unless the current code agrees.

## Stack

- Python 3.11+
- Click CLI and Rich terminal output
- Official MCP Python SDK with anyio
- Pydantic, PyYAML, json5, watchfiles
- pytest, ruff, mypy
- uv packaging and PyPI distribution

## How To Run

- Use `.codex/verify.commands` for routine verification.
- Current core checks are `uv run pytest`, `uv run ruff check`, and `uv run mypy src`.
- Use `mcp-audit discover` and `mcp-audit scan --skip-connect` for local config review without connecting to servers.

## Known Risks

- Never store, log, or transmit credential values; report environment variable key names only.
- Do not modify MCP client config files during scans.
- Keep optional LLM analysis opt-in only.
- Keep subprocess and server handling guarded by timeouts and cleanup.
- Do not call whole-repo mypy green while test-only typing debt remains.

## Next Recommended Move

Maintain the stable scanner and output contracts. For behavior changes, add focused fixtures or sample-scan assertions and update security/output docs when semantics change.

<!-- portfolio-context:end -->
