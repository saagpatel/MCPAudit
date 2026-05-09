# MCPAudit

## Communication Contract

- Follow `/Users/d/.codex/policies/communication/BigPictureReportingV1.md` for all user-facing updates.
- Use exact section labels from `BigPictureReportingV1.md` for default status/progress updates.
- Keep default updates beginner-friendly, big-picture, and low-noise.
- Keep technical details in internal artifacts unless explicitly requested by the user.

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
