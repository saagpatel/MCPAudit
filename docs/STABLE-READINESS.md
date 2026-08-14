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

## Current 2.7.0 Release State

The 2.7.0 release state is a backward-compatible minor release built after the
2.6.0 tag. Its primary capability groups are offline cache-contract,
authorization-posture, OAuth-transcript, task-lifecycle, result-parcel, and
session-resume laboratories plus deterministic delivery-evidence validation.
Existing 2.x audit-report and SARIF contracts remain additive. Source metadata,
the Action examples, and `server.json` are finalized for 2.7.0. That does not
prove public availability: PyPI was at 2.6.0 and the official MCP Registry was
at 2.5.0 on the last pre-release readback on 2026-08-14. Release evidence must
query each external surface again.

Release evidence must establish:

- package, lock metadata, changelog, versioned release notes,
  `docs/release-state.json`, `server.json`, and Action/pre-commit examples agree
  on 2.7.0; publication evidence must still report PyPI, the GitHub tag, the
  Action ref, and the official Registry entry separately;
- wheel and sdist metadata require `mcp>=1.28.1,<2.0` and expose `mcp-audit`,
  `mcp-audits`, and `proof-before-action`;
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

Merging the release-state PR does not authorize tagging, publication,
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
uv build --clear
```

Then verify clean installs from PyPI after publish:

```bash
uvx --from mcp-audits mcp-audit --version
python -m venv /tmp/mcp-audit-smoke
/tmp/mcp-audit-smoke/bin/python -m pip install mcp-audits
/tmp/mcp-audit-smoke/bin/mcp-audit --version
```
