# Beta And RC Readiness

This document records the beta and release-candidate bar used before stable
`1.0.0`.

## Readiness Bar

- Public docs match live CLI behavior.
- Default behavior stays local-first and deterministic.
- Connected scans, config-only scans, policy failures, and prompt/resource
  findings have output-contract fixtures.
- Real-world server validation corpus runs in the test suite.
- Adoption, security-review, pin-maintenance, and output-contract docs describe
  current behavior without aspirational claims.
- Known limitations are documented instead of implied away.
- Clean `uvx` and `pip` installs can run `mcp-audit --version`.

## Current Limitations

- Prompt/resource findings are visible and policy-gatable, but do not affect the
  composite server score yet. See `docs/PROMPT-RESOURCE-SCORING.md`.
- Pin maintenance remains explicit and server-scoped. See
  `docs/PIN-MAINTENANCE.md`.
- Whole-repo strict typing now passes and the canonical type gate is
  `uv run mypy .`.

## Verification Checklist

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

Clean-install smoke checks should verify both `uvx --prerelease allow` and a
temporary virtual environment with `pip install mcp-permission-audit`.
