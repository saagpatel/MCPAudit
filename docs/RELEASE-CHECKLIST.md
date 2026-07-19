# Release Checklist

Use this checklist before tagging a public MCPAudit alpha, beta, release
candidate, or stable release.

## Local Verifier

```bash
uv sync --dev --locked
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
git diff --check
uv lock --check
uv run python scripts/verify_release.py
uv build --clear
```

Remove generated `dist/` artifacts after the build check unless the release is
being uploaded manually.

## Candidate Metadata Check

- `pyproject.toml`, `server.json`, `docs/release-state.json`, and
  `CHANGELOG.md` agree on the candidate version.
- While `docs/release-state.json` has `status: candidate`, README Action and
  pre-commit examples continue to name the latest existing public tag. They
  must not advertise a tag that does not exist.
- `README.md`, `SECURITY.md`, `docs/OUTPUT-CONTRACT.md`,
  `docs/STABLE-READINESS.md`, and the versioned release notes match live CLI
  behavior.
- `mcp-audit --version` reports the release version.
- `mcp-audits` remains the PyPI distribution name and the installed
  `mcp-audit`, `mcp-audits`, and `proof-before-action` commands are present.
- Wheel and sdist metadata require `mcp>=1.28.1`; their contents contain no
  private paths, development caches, or generated local evidence.
- Record SHA-256 hashes for the exact wheel and sdist being considered for
  publication.

## Exact-Candidate Security Readback

- Record the exact candidate commit and re-query open Dependabot, code-scanning,
  and secret-scanning alerts against the live repository.
- Record each open alert with severity and disposition. A missing, masked,
  stale, or unavailable query is `UNKNOWN`, not zero.
- Confirm the candidate has a security-focused diff review and all reportable
  findings are either repaired or explicitly accepted by the release decision
  maker.
- Independent human review is required for a public release. If repository
  ownership makes that impossible, keep release status `NO-GO` until a reviewer
  or explicit residual-risk acceptance is available.

## Clean Install Smoke

Use an isolated cache for `uvx` so the check does not reuse an older local
install.

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp" uvx --prerelease allow --from mcp-audits mcp-audit --version
rm -r "$tmp"
```

Use a temporary virtual environment for a plain pip install check.

```bash
tmp="$(mktemp -d)"
python -m venv "$tmp/venv"
"$tmp/venv/bin/python" -m pip install mcp-audits
"$tmp/venv/bin/mcp-audit" --version
rm -r "$tmp"
```

## Finalize the Release State

Use a separate reviewed PR after the candidate has landed:

1. Change `docs/release-state.json` to `status: release` and set
   `published_version` to the candidate version.
2. Update README Action and pre-commit examples to the new public tag.
3. Replace `Unreleased` with the release date in `CHANGELOG.md` and finalize its
   comparison links.
4. Rerun the full local, security, metadata, build, and installed-command gates.

Merging a candidate or release-state PR does not authorize tagging or
publication.

## Publish (Separately Authorized)

1. Obtain separate publication approval naming the exact 40-character merge
   commit and `vX.Y.Z` tag. Confirm the `pypi` environment requires an
   independent reviewer; otherwise stop with `NO-GO`.
2. Create the tag only after that approval. Tag creation does not publish.
3. Manually dispatch `Publish to PyPI` with the exact tag, commit, and
   `publish-mcp-audits` confirmation. The workflow rechecks the tag/commit/main
   binding, release-state gate, lockfile, tests, style, types, package metadata,
   and clean build provenance.
4. Review the build job's wheel and sdist SHA-256 values before approving the
   protected `publish` job. That job downloads the exact retained artifact,
   verifies its hashes, and only then requests PyPI OIDC authority.
5. Confirm the PyPI release JSON and simple index include the new version.
6. Create or update the matching GitHub Release notes.

Never re-run or bypass a failed publish gate. Repair the release state through a
new reviewed commit and obtain a new exact approval.
