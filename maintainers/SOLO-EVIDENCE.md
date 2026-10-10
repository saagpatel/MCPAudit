# Solo Evidence

Solo evidence can reduce release risk, but it does not replace the two external
redacted reports required before a beta label.

## What Counts

- Clean install from PyPI with `uvx`.
- Clean virtualenv install with `pip`.
- Config-only scans against public or synthetic fixtures.
- JSON, SARIF, and HTML output parsing against committed fixtures.
- Policy-gate and SARIF upload demos using redacted public fixtures.

## What Does Not Count

- Private workstation configs.
- Credentialed connected scans.
- Reports that cannot be shared or fixture-converted.
- Local-only confidence without a downstream consumer or external setup shape.

## Current Use

Use solo evidence to keep launch mechanics honest:

```bash
uv run pytest -q
uv run ruff check .
uv run python scripts/launch_preflight.py
```

Then use external field reports to prove that the output contract survives
outside the maintainer environment.
