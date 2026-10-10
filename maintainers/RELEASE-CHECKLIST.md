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
candidate_commit="$(git rev-parse HEAD)"
uv build --clear --no-create-gitignore
uv run python scripts/verify_release.py \
  --commit "$candidate_commit" \
  --dist-dir dist
```

Remove generated `dist/` artifacts after the build check unless the release is
being uploaded manually.

## Candidate Metadata Check

- `pyproject.toml`, `docs/release-state.json`, and `CHANGELOG.md` agree on the
  candidate version.
- While `docs/release-state.json` has `status: candidate`, `server.json`,
  README Action examples, and pre-commit examples continue to name the latest
  existing public version/tag. They must not advertise a package or tag that
  does not exist.
- `README.md`, `SECURITY.md`, `docs/OUTPUT-CONTRACT.md`,
  `maintainers/STABLE-READINESS.md`, and the matching `CHANGELOG.md` section match live CLI
  behavior.
- Search `README.md` and `docs/guides/ci.md` for `MCPAudit@` references and
  confirm pinned versions match the public Action release.
- `mcp-audit --version` reports the release version.
- `mcp-audits` remains the PyPI distribution name and the installed
  `mcp-audit`, `mcp-audits`, and `proof-before-action` commands are present.
- Wheel and sdist metadata require `mcp>=2.2.0,<3.0`; their contents contain no
  private paths, development caches, or generated local evidence.
- Wheel and sdist metadata retain the `anyio>=4.14.2` security floor.
- Record SHA-256 hashes for the exact wheel and sdist being considered for
  publication.

## Exact-Candidate Security Readback

The advisory workflow and release gate query every public PyPI package/version
in the lock, including extras. OSV request size, response size, query count, and
request timeout are bounded. An unavailable or malformed feed exits 2 and fails
the gate; an advisory exits 1. No exception or suppression list is applied.
Saved-response fixture checks are offline tests, not current advisory evidence.
When exact build constraints are present, their package pins are included; missing
constraints are explicitly reported as unavailable build-input coverage. Toolchain
and image pins require separate verified upstream checksum evidence before release.

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

## Exact Candidate Install Smoke

Build from the exact clean candidate commit, verify its provenance, then install
the wheel and sdist directly. Do not use unversioned PyPI here: before
publication, that would exercise the previous public release.

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp/cache" uv venv "$tmp/wheel"
UV_CACHE_DIR="$tmp/cache" uv pip install \
  --python "$tmp/wheel/bin/python" ./dist/mcp_audits-X.Y.Z-py3-none-any.whl
"$tmp/wheel/bin/mcp-audit" --version
"$tmp/wheel/bin/mcp-audits" --version
"$tmp/wheel/bin/proof-before-action" --version
```

```bash
UV_CACHE_DIR="$tmp/cache" uv venv "$tmp/sdist"
UV_CACHE_DIR="$tmp/cache" uv pip install \
  --python "$tmp/sdist/bin/python" ./dist/mcp_audits-X.Y.Z.tar.gz
"$tmp/sdist/bin/mcp-audit" --version
"$tmp/sdist/bin/mcp-audits" --version
"$tmp/sdist/bin/proof-before-action" --version
rm -r "$tmp"
```

## Finalize the Release State

Use a separate reviewed PR after the candidate has landed:

1. Change `docs/release-state.json` to `status: release` and set
   `published_version` to the candidate version.
2. Update `server.json`, README Action examples, and pre-commit examples to the
   new public version/tag.
3. Change the `CHANGELOG.md` release-boundary markers to
   `Release status: approved` and `Publication decision: GO`; remove
   candidate-only authorization language.
4. Replace `Unreleased` with the release date in `CHANGELOG.md` and finalize its
   comparison links.
5. Rerun the full local, security, metadata, build, and installed-command gates.

Merging a candidate or release-state PR does not authorize tagging or
publication.

## Publish (Separately Authorized)

1. Obtain separate publication approval naming the exact 40-character merge
   commit and `vX.Y.Z` tag. Confirm the `pypi` environment requires a named
   repository-owner reviewer, disables administrator bypass, and has exactly one
   custom deployment policy for the `main` branch (no tag or wildcard policies);
   otherwise stop with `NO-GO`. Solo-maintainer approval remains permitted;
   stronger self-review protection is accepted. This is not independent
   review, so the publication approval must explicitly accept that limitation.
2. Create the tag only after that approval. Tag creation does not publish.
3. From the `main` branch, manually dispatch `Publish to PyPI` with the exact
   tag and commit. Use the default `dry_run: true` first; it runs the build and
   isolated consumer smoke without starting the OIDC publication job. A tag or
   feature-branch dispatch fails before the build. A
   typed confirmation is not authorization. The workflow reads back the live
   environment protections and rechecks the tag/commit/main binding,
   release-state gate, lockfile, tests, style, types, package metadata, and
   clean build provenance.
4. Review the build job's `release-manifest.json` and its SHA-256 before approval.
   It binds exactly two version-derived filenames and digests to both the source
   commit and workflow/control SHA. Dispatch with `dry_run: false` only for the
   separately approved publication. The protected `publish` job independently
   rechecks the file set and hashes. OIDC capability is granted to the entire job;
   its earlier steps already possess that capability before hash verification.
   Consumer install smokes run in a separate read-only job using disposable
   copies, with no write authority over the retained publication candidates.
5. Confirm the PyPI release JSON and simple index include the new version.
6. Create or update the matching GitHub Release notes and attach the approved
   `release-manifest.json` as a durable asset. Retain its independently reviewed
   SHA-256 for the Registry dispatch; the short-lived workflow artifact alone is
   not a durable approval record.
7. Confirm the existing protected `pypi` release environment still has required
   reviewers with administrator bypass disabled. The Registry workflow reuses
   this gate for a separate post-PyPI approval rather than creating a second,
   potentially unprotected environment on first use.
8. From `main`, manually dispatch `Publish to MCP Registry` with the same exact
   tag, commit, and approved manifest SHA-256 only after PyPI and GitHub Release readback. Its validation job
   proves the PyPI prerequisite, release binding, protected environment, pinned
   publisher hash, exact descriptor tuple, and non-yanked PyPI filenames and
   SHA-256 values before the environment-bound OIDC
   job can run.
   The publish job rechecks the shared environment policy, approved PyPI manifest,
   and exact descriptor immediately before login, then uses the same tuple
   assertion for the official Registry readbacks.
9. Confirm both the exact-version and `latest` official Registry endpoints name
   `io.github.saagpatel/mcp-audit` at the released version with the exact PyPI package
   tuple. Registry metadata does not prove artifact hashes, installation,
   runtime uptake, adoption, or human effectiveness.

Never re-run or bypass a failed publish gate. Repair the release state through a
new reviewed commit and obtain a new exact approval.

## Post-Publication Install Smoke

After PyPI readback proves the new version exists, use an isolated cache so the
check cannot reuse a local candidate install:

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp" uvx --from "mcp-audits==X.Y.Z" mcp-audit --version
UV_CACHE_DIR="$tmp" uvx --from "mcp-audits==X.Y.Z" proof-before-action --version
rm -r "$tmp"
```
