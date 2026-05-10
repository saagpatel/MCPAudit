# Beta And RC Readiness

This document records the beta and release-candidate bar used for current
`1.x` releases. MCPAudit `1.5.3` is a beta-readiness intake polish release, not
a beta cut.

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
- At least two external redacted reports confirm the current output contract is
  stable for downstream consumers before a beta label is used.

## Current Limitations

- Prompt/resource findings are visible and policy-gatable, but do not affect the
  composite server score yet. See `docs/PROMPT-RESOURCE-SCORING.md`.
- Pin maintenance remains explicit and server-scoped. See
  `docs/PIN-MAINTENANCE.md`.
- Whole-repo strict typing now passes and the canonical type gate is
  `uv run mypy .`.
- Output-contract upgrade compatibility is fixture-tested for older report
  shapes and additive future fields. See `docs/OUTPUT-CONTRACT.md`.
- Field-report intake is documented and has a dedicated public issue template.
  See `docs/FIELD-REPORTS.md`.

## Current Decision

Ship `1.5.3` as polish instead of `1.6.0` or beta.

The current evidence strengthens compatibility confidence and makes external
field-report intake easier, but it is still mostly local and fixture-based. Move
to beta only after external redacted reports show that downstream consumers can
safely rely on the current JSON/SARIF shapes.

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
