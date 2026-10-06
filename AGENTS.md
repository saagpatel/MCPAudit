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

## Local Verification

Use the smallest check that exercises the requested change. Commands run from the repository root; use the existing environment. For checks that must avoid dependency resolution or downloads, add `--offline --no-sync` after `uv run`. If the environment is missing, report that prerequisite rather than silently changing dependencies.

```sh
# Focused test: replace the path/node with the affected test.
uv run pytest -p no:cacheprovider -q tests/test_scorer.py

# Lint, formatting, and the CI type-check selection.
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy .

# CLI entry point.
uv run mcp-audit --help

# Synthetic config-only smoke: no workstation config discovery or server connections.
uv run mcp-audit scan \
  --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only --skip-connect --override-config /dev/null
```

`--skip-connect` alone still discovers workstation MCP configs. The explicit fixture, `--config-only`, and empty override above keep this smoke confined to synthetic input. On Windows, replace `/dev/null` with a task-owned empty YAML file. Bare `scan` and `make audit` inspect workstation configs and may connect to servers; use them only when the task calls for that scope.

For broader verification, use `uv run pytest -p no:cacheprovider -q tests/`. The [CONTRIBUTING test lanes](CONTRIBUTING.md#running-tests) define Docker, PostgreSQL, Node, and macOS prerequisites. Tests can launch disposable fixture processes; skipped capabilities remain unverified. Run package/build checks when packaging is affected, using the [release checklist](maintainers/RELEASE-CHECKLIST.md).

Browser checks apply to HTML report or sandbox changes. For the static synthetic sandbox, run `python3 -m http.server 8765 --bind 127.0.0.1 --directory examples/sandbox` and open `http://127.0.0.1:8765/`; choose another free port if needed and stop the server when finished. Follow [the sandbox guide](examples/sandbox/README.md) for fixture and report checks. Ordinary CLI/library changes do not need a browser.

## Known Risks

- MCP config auditing can expose sensitive config shape. Report environment variable key names only, never values.
- Do not read `.env` files, keychains, OAuth stores, browser profiles, raw logs, private transcripts, cookies, or credential-bearing configs.
- Treat remote package verification, downloads, LLM analysis, and connected server scans as higher-reach modes that need explicit justification.

## Review guidelines

Focus Codex review on scan correctness, silent skipped checks, degraded-state
warnings, report schema compatibility, secret exposure in findings/warnings,
and release or registry drift. Treat comments on missing tests as merge-relevant
when the change touches detectors, report fields, scan modes, package
verification, SARIF/JSON/HTML output, or MCP connection behavior.

For docs-only PRs, comment only when the docs claim a scan, safety property,
output field, release version, or verification path that is not supported by
the reviewed tree.

## Contributing

See `CONTRIBUTING.md` for the full contribution guide. Before opening a PR:

- Run `uv run pytest -q` and confirm all tests pass.
- Run `uv run ruff check .` and `uv run ruff format --check` (zero findings expected).
- For new detectors or report fields, add fixture-backed tests and update `docs/OUTPUT-CONTRACT.md`.
- Prefer explicit synthetic configs with `--config-only --skip-connect`; connected fixtures require explicit justification.

<!-- portfolio-context:start -->
# Portfolio Context

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

Use the authoritative **Local Verification** section above for focused tests, the isolated synthetic CLI smoke, and conditional browser checks. Use [CONTRIBUTING.md](CONTRIBUTING.md#running-tests) for broader and capability-specific lanes.

## Known Risks

- MCP config auditing can expose sensitive config shape. Report environment variable key names only, never values.
- Do not read `.env` files, keychains, OAuth stores, browser profiles, raw logs, private transcripts, cookies, or credential-bearing configs.
- Treat remote package verification, downloads, LLM analysis, and connected server scans as higher-reach modes that need explicit justification.

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
