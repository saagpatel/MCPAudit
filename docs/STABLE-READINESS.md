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

## Current 2.5.0 Release

The 2.5.0 release is a backward-compatible minor release. It adds Proof Before
Action, ProofOS PostgreSQL verification, SafeForge runtime/pre-install evidence,
and the security dependency/pinning repairs recorded in the changelog. Existing
2.x audit-report and SARIF contracts remain additive.

Release evidence must establish:

- package, changelog, `docs/release-state.json`, `server.json`, and public
  Action/pre-commit examples agree on the 2.5.0 public release;
- wheel and sdist metadata require `mcp>=1.28.1` and expose `mcp-audit`,
  `mcp-audits`, and `proof-before-action`;
- the full quality gate and an installed Proof Before Action workflow pass from
  an exact clean candidate commit;
- missing, stale, masked, unmatched, incomplete, or unobservable evidence never
  becomes a safety claim;
- the remaining OpenSSF human-review, fuzzing, and best-practices-badge findings
  have explicit evidence-backed dispositions.

Tagging, publishing, and external registry changes remain separate actions. Tag
creation no longer triggers publication: the publish workflow requires a manual
dispatch bound to an exact tag and commit, verifies the release state, and
exposes artifact hashes before the environment-bound OIDC job. The `pypi`
environment requires an independent reviewer, prevents self-review, and disables
administrator bypass. The unresolved human-review, fuzzing, and best-practices
Scorecard findings are accepted release limitations, and the absence of two
external redacted field reports remains a limitation: solo fixture evidence does
not prove downstream adoption or broad environment compatibility.

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
uv build --clear
```

Then verify clean installs from PyPI after publish:

```bash
uvx --from mcp-audits mcp-audit --version
python -m venv /tmp/mcp-audit-smoke
/tmp/mcp-audit-smoke/bin/python -m pip install mcp-audits
/tmp/mcp-audit-smoke/bin/mcp-audit --version
```
