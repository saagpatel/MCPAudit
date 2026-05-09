# Stable Readiness

This document records the release bar used for the `1.0.0` stable release.
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

## Current Status

Ready for stable release:

- package install and command naming are settled;
- connected and config-only scan boundaries are documented;
- JSON/SARIF rule IDs are documented and snapshot-tested;
- user feedback has a fixture-driven intake path;
- validation corpus covers common filesystem, network, shell, destructive,
  exfiltration, browser, cloud, database, and messaging server shapes.
- whole-repo strict typing passes with `uv run mypy .`.

Release-candidate decision:

- keep prompt/resource findings outside `risk_score.composite` for `1.0.0`;
- consider an additive `non_tool_risk` field after stable if field feedback
  shows enough calibrated signal.

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
uvx --from mcp-permission-audit mcp-audit --version
python -m venv /tmp/mcp-audit-smoke
/tmp/mcp-audit-smoke/bin/python -m pip install mcp-permission-audit
/tmp/mcp-audit-smoke/bin/mcp-audit --version
```
