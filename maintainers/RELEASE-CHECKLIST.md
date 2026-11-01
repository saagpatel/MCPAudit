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

`--dist-dir` binds the artifacts to the approved commit's content, not only to
its provenance file. A reference wheel and sdist build from `git archive COMMIT`
in a temporary clean export determines the complete packaged file sets using
the approved backend's include and exclude rules. The reference build runs
`uv build --offline --no-create-gitignore`, so its build requirements must already
be cached; an unavailable reference build fails verification. Every non-generated
path must be present, extra paths are rejected, and every sdist file must be
byte-identical to that path at the commit, apart from the build-generated
`PKG-INFO`, provenance file, and uv_build's
normalized `pyproject.toml` (which must parse identically to the commit's, while
`pyproject.toml.orig` keeps its exact bytes). A wheel may hold only its
`.dist-info/` and the contracted module, each module file byte-identical to the
commit's source and every file listed in `RECORD`; `.data/` members are
rejected. Wheel `METADATA` and sdist `PKG-INFO` must declare exactly the dependencies
and optional dependencies from the approved commit's `pyproject.toml`, combining
optional requirements' existing markers with their extra markers. The reference
build supplies the backend's normalized marker expressions; dependency names,
URLs, extras, specifiers, and declaration counts are checked against the committed
pyproject independently. Extra, missing, and duplicate requirements fail.
Requirements are compared as parsed `packaging`
requirements (canonical name, URL, extras, specifier set, and normalized marker),
so a quoted marker value such as `extra == "labs "` never passes as `labs`.

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

For the 2.11.0 Phase 0 code-scanning readback, record alerts #42, #43, and
#44 as false positives: the PyPI and MCP Registry publish workflows do not use
the Actions cache, and every `setup-uv` step disables its cache. Record alert
#47 as a false positive because the pin-parse warning logs only the exception
class and position, not the parsed input. The maintainer records these
dispositions through the GitHub API; this note and the regression test do not
dismiss alerts.

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

## Publish the Current Unsplit Package (Separately Authorized)

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
On this `release/2.x` branch, steps 7-9 use the branch-local workflows: the
environment is `pypi-2x` (exactly one branch policy, `release/2.x`), dispatch
is from `release/2.x` (main is refused), and step 9 confirms only the
exact-version Registry endpoint, because 3.x remains `latest`.

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

## Three-Distribution Release Train (Groundwork; Not Active Yet)

The current package is still unsplit. The following contract takes effect when
the separate distribution projects land; it does not authorize publication or
change the current workflows. Before activation, refactor their tag-first gates
to verify an approved commit before publication and create the tag afterwards.
Do not use the unsplit workflow's tag-first sequence for a split release.

All three distributions use one version and one clean source commit. Publish in
this order: **mcp-audits (core), mcp-audits-labs, mcp-audits-proof**. Core extras
`[labs]`, `[proof]`, and `[all]` pin the relevant satellites with `==X.Y.Z`;
satellites pin core with `==X.Y.Z`. Verify every wheel and sdist before upload.
For `uv tool`, install `mcp-audits-proof` directly to put `proof-before-action`
on PATH; installing core with an extra does not expose the extra's scripts.
Include this instruction in every split-install or migration notice.

Pass a reviewed JSON contract with `--distributions FILE` to every verifier
invocation (including publication checks). It is a list in publication order;
each entry has `name`, `module`, `module_root`, `project`, and `scripts`. Paths
are relative to the checkout, and `project` identifies that distribution's
pyproject. For example, the future layout could use:

```json
[
  {"name": "mcp-audits", "module": "mcp_audit", "module_root": "src",
   "project": "pyproject.toml",
   "scripts": {"mcp-audit": "mcp_audit.cli:main", "mcp-audits": "mcp_audit.cli:main"}},
  {"name": "mcp-audits-labs", "module": "mcp_audit_labs", "module_root": "src",
   "project": "distributions/labs/pyproject.toml", "scripts": {}},
  {"name": "mcp-audits-proof", "module": "proof_before_action", "module_root": "src",
   "project": "distributions/proof/pyproject.toml",
   "scripts": {"proof-before-action": "proof_before_action.proof_cli:main"}}
]
```

This is an example contract, not an implemented layout or entry point. The
default remains the current single package and its three scripts. The backend
uses each build project's `[tool.uv.build-backend]` `module-name` and
`module-root` (default `src`) to locate its provenance file and tracked sources.
Keep the wrapper beside that build project's pyproject; the actual split must
arrange those build roots. The source verifier requires all three project
versions in the checkout's shared `uv.lock`.
Proof derives its checkout path from its Python package; a changed source
layout can supply `_producer_state(source_path=Path(...))` explicitly. Installed
Proof still uses its own adjacent embedded provenance first.

1. Build all six artifacts from the same approved clean commit and verify
   them together in one `dist/` directory. Use the same contract for metadata,
   scripts, provenance, manifest creation, and artifact rechecks. Retain the
   manifest and its independently approved SHA-256; it names all six files.
2. Run isolated wheel and sdist install smokes for each distribution and for
   the exact-pinned extras. Prepare all trusted-publisher destinations before
   the first upload. Obtain exact source and control-revision approval.
3. Upload core, then labs, then proof, using only the approved artifacts.
   Read back each distribution's exact-version PyPI JSON, filenames, non-yanked
   status and SHA-256. For the verifier's `--publication-check pypi`, provide
   one JSON object keyed by all three distribution names, whose values are the
   respective PyPI responses; verify against the approved six-file manifest.
4. **No tag, GitHub Release, Registry entry, or Action ref advances until all
   three pinned wheels and sdists are published and verified.** Only then
   create the tag at the approved commit, attach the durable manifest to the
   GitHub Release, and run the gated Registry and Action-ref updates. Check
   the exact package, Action and hook readbacks; no moving ref is build proof.

### Partial-Publication Recovery

If any upload or readback fails, freeze every public release pointer. Record
which of the six approved files exist, their digests and yanked status. Retain
the previous complete release as the documented package, Action and hook
rollback target. A partly published version can have unavailable exact pins;
do not advertise it as installable.

For a transient failure, read back already uploaded files against the original
manifest. If they match, obtain approval to resume only missing files in
core/labs/proof order, with the original source, control revision and bytes.
Never rebuild, overwrite files, blindly rerun the entire upload, or use
`--skip-existing` as verification. Recheck all six files before advancing any
pointer. An existing filename with a different digest stops recovery.

If any published artifact is wrong or completion is impossible, do not reuse
the version. With explicit approval, yank the partial release's uploaded files
with a reason; deletion is not rollback. Prepare a new lockstep patch version,
update every exact pin through review, rebuild all six artifacts and repeat the
full approval and verification gates. Record the abandoned version and link
the recovery release in its notes. Neither a yank nor a retry establishes a
complete release by itself.

## `release/2.x` Security Maintenance

Create `release/2.x` from the last supported 2.x release commit before 3.0
development diverges. Keep its own `docs/release-state.json`, pyproject,
lockfile, changelog, Registry descriptor, Action and hook references on that
branch; never copy main's 3.x release state into it. Backport only reviewed
security fixes for the package, Action and hook, with branch-local patch
versions and the ordinary release gates. Do not merge main wholesale.

Support ends **120 calendar days after 3.0.0**. Publish the explicit end date
and the package, Action and hook backport surfaces in the 3.0.0 notes. After
that date, stop 2.x security releases unless the owner approves a new policy.

Run `scripts/verify_release.py --root CHECKOUT --release-branch release/2.x`
against the branch checkout. It checks that checkout's release state and
requires a 2.x version; with `--require-publishable`, the approved commit must
be an ancestor of `origin/release/2.x`. Publication environment readbacks must
allow exactly `release/2.x`, with the same reviewer and bypass protections as
main. The default verifier continues to require main. Use the branch's own
unsplit contract unless a separately approved 2.x packaging change exists.

This branch's `publish.yml` and `publish-mcp-registry.yml` accept dispatch only
from `refs/heads/release/2.x`, bind to the `pypi-2x` environment, and pass
`--release-branch release/2.x` to every verifier call. Before the first
maintenance release, create the `pypi-2x` GitHub environment with exactly the
`release/2.x` branch policy, the same reviewer and admin-bypass protections as
`pypi`, and a matching PyPI trusted publisher; the workflows fail closed until
both exist. Keep main's environment main-only. Do not weaken either gate to a
wildcard or dispatch maintenance releases through main. Run dry-run and
exact-artifact gates on this branch, then verify its package, Action and hook
after release.

## Post-Publication Install Smoke

After PyPI readback proves the new version exists, use an isolated cache so the
check cannot reuse a local candidate install:

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp" uvx --from "mcp-audits==X.Y.Z" mcp-audit --version
UV_CACHE_DIR="$tmp" uvx --from "mcp-audits==X.Y.Z" proof-before-action --version
rm -r "$tmp"
```
