# Release Checklist

Use this checklist before tagging a public MCPAudit alpha, beta, release
candidate, or stable release.

## Local Verifier

```bash
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
git diff --check
uv build --clear
```

Remove generated `dist/` artifacts after the build check unless the release is
being uploaded manually.

## Metadata Check

- `pyproject.toml` version matches `CHANGELOG.md`.
- `README.md`, `SECURITY.md`, and `IMPLEMENTATION-ROADMAP.md` match live CLI
  behavior.
- `mcp-audit --version` reports the release version.
- `mcp-permission-audit` remains the PyPI distribution name and `mcp-audit`
  remains the installed command.

## Clean Install Smoke

Use an isolated cache for `uvx` so the check does not reuse an older local
install.

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp" uvx --prerelease allow --from mcp-permission-audit mcp-audit --version
rm -r "$tmp"
```

Use a temporary virtual environment for a plain pip install check.

```bash
tmp="$(mktemp -d)"
python -m venv "$tmp/venv"
"$tmp/venv/bin/python" -m pip install mcp-permission-audit
"$tmp/venv/bin/mcp-audit" --version
rm -r "$tmp"
```

## Publish

1. Merge the release PR after CI passes.
2. Tag the merge commit as `vX.Y.Z`.
3. Confirm the `Publish to PyPI` workflow succeeds.
4. Confirm the PyPI release JSON and simple index include the new version.
5. Create or update the matching GitHub Release notes.
