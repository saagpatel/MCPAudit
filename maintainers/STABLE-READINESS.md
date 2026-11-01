# Stable Readiness

This document records the release bar used for stable releases.
It is intentionally evidence-based: an item is ready only when the code, docs,
tests, and install path agree.

## Stable Release Bar

- Output contract fixtures and golden snapshots cover JSON and SARIF shape for
  connected, failed, config-only, policy-failed, prompt/resource-heavy, drift,
  and tool-target reports.
- Prompt/resource findings have a documented scoring migration decision.
- Public docs do not make stale or aspirational claims.
- `uvx` and `pip` install paths work from PyPI.
- Policy examples cover local review, balanced CI, strict reviewed-server CI,
  reviewed local workstations, and approved-server-only CI.
- Security review notes are current for config parsing, connection lifecycle,
  redaction, SARIF/AI-consumption risks, and optional LLM behavior.
- Known limitations are documented in release notes and beta/stable readiness
  docs.

## Current 3.0.0 Release State

The 3.0.0 source state is the boundary release: the package splits into the lockstep `mcp-audits`,
`mcp-audits-labs` and `mcp-audits-proof` distributions, `scan` becomes a
legacy interceptor over `check` with the D22 exact translation, deprecated
commands and aliases are removed, `serve`'s `scan_mcp_servers` is static by
default, v1 pin baselines are withheld and fail requested pin-dependent
checks, and release tooling publishes three distributions commit-first.
Breaking changes are listed in the [migration guide](../docs/3.0-MIGRATION.md).
Upgrade notes and remaining limitations are recorded in the changelog and
[release notes](../docs/3.0-RELEASE-NOTES.md). The supported MCP dependency
remains `mcp>=2.2.0,<3.0`, and `schema_version` is unchanged. Package and lock
metadata for all three distributions, `server.json`, Action examples, and
pre-commit examples identify 3.0.0. That does not prove public availability:
release evidence must query PyPI for all three projects, GitHub, and the
official MCP Registry separately.

Release evidence must establish:

- package, lock metadata for all three distributions, changelog release
  section, versioned release notes, `docs/release-state.json`, `server.json`,
  and Action/pre-commit examples agree on 3.0.0; publication evidence must
  still report PyPI for all six files, the GitHub tag, the Action ref, and the
  official Registry entry separately;
- wheel and sdist metadata require `mcp>=2.2.0,<3.0` and expose `mcp-audit`
  and `mcp-audits`; core must not provide `proof-before-action`, which the
  `mcp-audits-proof` wheel and sdist expose instead;
- focused capability tests, output-contract checks, the full quality gate, the
  release verifier, and wheel/sdist install smokes pass from an exact clean
  release commit;
- missing, stale, masked, unmatched, incomplete, or unobservable evidence never
  becomes a safety claim;
- Agent UI evidence remains offline, static, descriptor-bound, and limited to
  supported fixture contracts;
- evidence-to-enforcement remains experimental, fixture-only, and does not
  authorize or prove a production gateway;
- SSRF evidence remains static and schema-derived and does not prove runtime
  containment or host safety.

Merging the candidate or release-state PR does not authorize tagging, publication,
deployment, or an external Registry update. A separate exact-commit publication
decision is still required. Tag creation does not publish: the manual workflows
bind an exact tag and commit, verify release state and public prerequisites, and
keep OIDC authority inside protected publish jobs. Automated review and fixture
coverage do not replace independent human review. Missing field reports and
other unverifiable external evidence remain `UNKNOWN` and do not establish
downstream adoption, human effectiveness, or broad environment compatibility.

## Go/No-Go Checklist

Run before tagging stable:

```bash
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
uv lock --check
git diff --check
uv run python tests/validation/validate_patterns.py
uv build --clear --build-constraints build-constraints.txt
```

Release builds pin the build backend through `build-constraints.txt`; the
[release checklist](RELEASE-CHECKLIST.md) is the current release procedure.

Then verify clean installs from PyPI after publish:

```bash
uvx --from mcp-audits mcp-audit --version
python -m venv /tmp/mcp-audit-smoke
/tmp/mcp-audit-smoke/bin/python -m pip install mcp-audits
/tmp/mcp-audit-smoke/bin/mcp-audit --version
```
