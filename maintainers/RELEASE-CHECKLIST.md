# Release Checklist

Use this checklist before publishing a public MCPAudit alpha, beta, release
candidate, or stable release. 3.x releases are commit-first: publication is
bound to an approved commit and version, and the `vX.Y.Z` tag is created only
after all six distribution files are published and verified.

## Local Verifier

```bash
uv sync --all-packages --dev --locked
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
git diff --check
uv lock --check
uv run python scripts/verify_release.py --distributions release/distributions.json
candidate_commit="$(git rev-parse HEAD)"
uv build --all-packages --clear --no-create-gitignore \
  --build-constraints build-constraints.txt
uv run python scripts/verify_release.py \
  --distributions release/distributions.json \
  --commit "$candidate_commit" \
  --dist-dir dist
```

Remove generated `dist/` artifacts after the build check unless the release is
being uploaded manually.

`--dist-dir` binds the artifacts to the approved commit's content, not only to
its provenance file. A reference wheel and sdist build from `git archive COMMIT`
in a temporary clean export determines the complete packaged file sets using
the approved backend's include and exclude rules. The reference build runs
`uv build --offline --no-create-gitignore --build-constraints` with the approved
commit's `build-constraints.txt`, so its build requirements must already be cached;
a missing constraints file or an unavailable reference build fails verification. Every non-generated
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
  `mcp-audit` and `mcp-audits` commands are present. Core must not provide
  `proof-before-action`; that script ships only in the `mcp-audits-proof`
  wheel and sdist, which report the release version.
- Wheel and sdist metadata require `mcp>=2.2.0,<3.0`; their contents contain no
  private paths, development caches, or generated local evidence.
- Wheel and sdist metadata retain the `anyio>=4.14.2` security floor.
- Record SHA-256 hashes for the exact six files (a wheel and an sdist for each
  of core, Labs and Proof) being considered for publication.

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
The exact build pins in `build-constraints.txt` are always included; a missing
constraints file exits 2 and fails the gate. The CI build reads the trusted-controls
copy of `build-constraints.txt` and the reference build reads the approved commit's
copy; the build job requires the two to be identical, and the exact `pyproject.toml`
pin makes any mismatch unbuildable. Toolchain
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
test ! -e "$tmp/wheel/bin/proof-before-action"  # core must not provide it
UV_CACHE_DIR="$tmp/cache" uv venv "$tmp/proof-wheel"
UV_CACHE_DIR="$tmp/cache" uv pip install \
  --python "$tmp/proof-wheel/bin/python" ./dist/mcp_audits_proof-X.Y.Z-py3-none-any.whl
"$tmp/proof-wheel/bin/proof-before-action" --version
```

```bash
UV_CACHE_DIR="$tmp/cache" uv venv "$tmp/sdist"
UV_CACHE_DIR="$tmp/cache" uv pip install \
  --python "$tmp/sdist/bin/python" ./dist/mcp_audits-X.Y.Z.tar.gz
"$tmp/sdist/bin/mcp-audit" --version
"$tmp/sdist/bin/mcp-audits" --version
test ! -e "$tmp/sdist/bin/proof-before-action"  # core must not provide it
UV_CACHE_DIR="$tmp/cache" uv venv "$tmp/proof-sdist"
UV_CACHE_DIR="$tmp/cache" uv pip install \
  --python "$tmp/proof-sdist/bin/python" ./dist/mcp_audits_proof-X.Y.Z.tar.gz
"$tmp/proof-sdist/bin/proof-before-action" --version
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

## Three-Distribution Release Train

Every release after 2.x ships as three lockstep distributions from one version
and one clean source commit: **mcp-audits (core), mcp-audits-labs,
mcp-audits-proof**, published in that order. Core extras `[labs]`, `[proof]`,
and `[all]` pin the relevant satellites with `==X.Y.Z`; satellites pin core with
`==X.Y.Z`. For `uv tool`, install `mcp-audits-proof` directly to put
`proof-before-action` on PATH; installing core with an extra does not expose the
extra's scripts. Include this instruction in every split-install or migration
notice.

The reviewed contract is the committed `release/distributions.json`. It is a
list in publication order; each entry has `name`, `module`, `module_root`,
`project`, and `scripts`, with paths relative to the checkout. Pass it with
`--distributions release/distributions.json` to every verifier invocation,
including publication checks. Any 3.x (or later) version fails closed without
it, and an unsplit or reordered contract is rejected. The source copy, the
release-controls copy and the copy at the approved commit must be byte
identical. The backend uses each build project's `[tool.uv.build-backend]`
`module-name` and `module-root` (default `src`) to locate its provenance file
and tracked sources, and the source verifier requires all three project
versions in the shared `uv.lock`. Installed Proof uses its own adjacent
embedded provenance first.

The `release/2.x` line keeps its unsplit contract on its own branch; see
[2.x security maintenance](#release2x-security-maintenance).

## Publish a 3.x Release (Commit-First, Separately Authorized)

The release is bound to an approved commit and version, not to a tag. Main's
`Publish to PyPI` workflow takes `commit` and `version` inputs, refuses an
existing `vX.Y.Z` tag, and refuses any 2.x version. The tag is created only
after all six files are published and verified.

### Owner Prerequisites

- PyPI trusted publishers exist for `mcp-audits-labs` and `mcp-audits-proof`,
  each bound to this repository, the `publish.yml` workflow and the `pypi`
  environment, alongside the existing `mcp-audits` publisher. Prepare all
  three before the first live run: a missing satellite publisher fails after
  core is already uploaded and leaves a partial publication.
- The `pypi` environment requires a named repository-owner reviewer, disables
  administrator bypass, and has exactly one custom deployment policy for the
  `main` branch (no tag or wildcard policies); otherwise stop with `NO-GO`.
  Solo-maintainer approval remains permitted; stronger self-review protection
  is accepted. This is not independent review, so the publication approval
  must explicitly accept that limitation.

### Rehearsal Before the First Split Release

Run the pre-release rehearsal dry run only after item S-2 (labs moved into
`mcp_audit_labs`) is on `main`. The consumer smoke expects core-only
`mcp-audit lab agent-ui --help` to exit 2 with the Labs install notice, which
holds only once the lab modules live in `mcp_audit_labs`. The dry run also
rehearses a simulated partial upload and the retained-byte resume path end to
end without publication authority.

### Dry Run and Publication

1. Obtain separate publication approval naming the exact 40-character merge
   commit and the `X.Y.Z` version. Do not create the tag: every pre-publication
   check fails with `release tag must not exist before publication` while
   `vX.Y.Z` exists. Merging a candidate or release-state PR does not authorize
   publication.
2. From the `main` branch, manually dispatch `Publish to PyPI` with the exact
   `commit` and `version`, leaving the default `dry_run: true`. A feature-branch
   dispatch, a 2.x version, or recovery inputs without `resume` fail before the
   build. A typed confirmation is not authorization. The build job reads back
   the live environment protections and rechecks the commit/main binding,
   absent tag, release-state gate, distribution contract, advisories, lockfile,
   tests, style, types and clean build provenance, then builds all workspace
   packages.
3. Review the build job's `release-manifest.json` and the `manifest SHA-256`
   it logs. The manifest binds exactly six version-derived filenames (a wheel
   and an sdist for each distribution) and their digests to both the source
   commit and the workflow/control SHA. The consumer smoke installs every
   wheel and sdist and each exact-pinned extra offline from disposable copies,
   runs `proof-before-action` wherever the Proof distribution is installed,
   asserts that core and Labs alone do not provide it, and rechecks the file
   set and digests afterwards.
   The candidate artifact `mcp-audits-X.Y.Z` is retained for 90 days.
4. Dispatch again with `dry_run: false` only for the separately approved
   publication. The protected `publish` job waits for the owner's `pypi`
   environment approval; approve it only after reviewing that run's manifest
   and SHA-256, which differ from the dry run's because the run rebuilds. To
   publish the exact dry-run bytes instead, use [Resume](#resume) against the
   dry-run run. OIDC capability is granted to the entire job; its earlier steps
   already possess that capability before hash verification.
5. The `publish` job re-reads the environment, rechecks the landed source and
   the absent tag, downloads the retained candidates, verifies them against the
   manifest, and stages each distribution in its own folder. It then uploads
   core, reads back `mcp-audits` with `--publication-check pypi
   --published-through mcp-audits`, uploads labs and reads back through
   `mcp-audits-labs`, uploads proof and reads back through `mcp-audits-proof`,
   and finally requires the complete six-file publication. It stops on the
   first failure. If the version already partly exists on PyPI, a non-resume
   run refuses to stage; use [Resume](#resume).

### Interim Install State

Between the core upload and the final six-file readback, the version is only
partly installable. While core is published but labs and proof are not,
`mcp-audits[labs]==X.Y.Z` (and `[proof]` and `[all]`) cannot resolve, and
`mcp-audits-proof==X.Y.Z` does not exist. Plain `mcp-audits==X.Y.Z` may install.
Do not advertise, announce or smoke the new version as installable in this
state. **Every public pointer stays frozen until all six files verify:** no
tag, GitHub Release, Registry entry, Action ref or hook ref advances, and the
previous complete release remains the documented install, Action and hook
target. References that the merged release state already names as `vX.Y.Z`
do not resolve until the tag exists; do not point users at them. If the run
cannot complete, follow
[Partial-Publication Recovery](#partial-publication-recovery).

### Tag, GitHub Release and Registry

Only after the publish job's six-file check succeeds:

1. The owner creates the lightweight `vX.Y.Z` tag at the approved commit and
   pushes it. Tag creation does not publish.

   ```bash
   git fetch --force --tags origin main
   git tag "vX.Y.Z" "$approved_commit"
   git push origin "refs/tags/vX.Y.Z"
   ```

2. Verify all six PyPI files and the tag together from a clean checkout of the
   approved commit. Keep the downloaded manifest and readbacks outside the
   checkout, because the verifier rejects a dirty tree.

   ```bash
   tmp="$(mktemp -d)"
   gh run download "$run_id" --name "mcp-audits-X.Y.Z" --dir "$tmp/release"
   for name in mcp-audits mcp-audits-labs mcp-audits-proof; do
     curl --fail --silent --show-error \
       "https://pypi.org/pypi/$name/X.Y.Z/json" --output "$tmp/pypi-$name.json"
   done
   python3 -c 'import json, sys; print(json.dumps({n: json.load(open(f"{sys.argv[1]}/pypi-{n}.json")) for n in ("mcp-audits", "mcp-audits-labs", "mcp-audits-proof")}))' \
     "$tmp" > "$tmp/pypi-readback.json"
   git switch --detach "$approved_commit"
   uv run --no-project --with packaging==26.0 python scripts/verify_release.py \
     --distributions release/distributions.json --publication-check tag \
     --tag "vX.Y.Z" --commit "$approved_commit" --workflow-sha "$control_sha" \
     --manifest "$tmp/release/release-manifest.json" \
     --manifest-sha256 "$manifest_sha256" --response-json "$tmp/pypi-readback.json"
   ```

   `run_id`, `control_sha` and `manifest_sha256` are the publishing run's
   values (for a resumed publication, the original run's; see
   [Resume](#resume)).
3. Create the GitHub Release from the existing tag and attach the approved
   manifest as a durable asset. Retain its independently reviewed SHA-256 for
   the Registry dispatch; the 90-day workflow artifact alone is not a durable
   approval record.

   ```bash
   gh release create "vX.Y.Z" --verify-tag --latest \
     --title "vX.Y.Z" --notes-file RELEASE_NOTES.md \
     "$tmp/release/release-manifest.json"
   ```

4. Confirm the protected `pypi` environment still has required reviewers with
   administrator bypass disabled. The Registry workflow reuses this gate for a
   separate post-PyPI approval rather than creating a second, potentially
   unprotected environment on first use.
5. From `main`, manually dispatch `Publish to MCP Registry` with the exact
   `vX.Y.Z` tag, the approved commit, and the approved manifest SHA-256. Its
   validation job downloads the manifest from the GitHub Release, reads back
   all three distributions from PyPI keyed by name, and proves the release
   binding, protected environment, pinned publisher hash, exact descriptor
   tuple, and non-yanked PyPI filenames and SHA-256 values before the
   environment-bound OIDC job can run. The publish job rechecks the shared
   environment policy, the three-way PyPI readback and the exact descriptor
   immediately before login.
   Dispatch it while main's `project.version` still equals the release
   version: the verifier requires the tag to match the release-controls
   checkout's version, so once a later version bump lands on main these
   checks fail closed and the Registry entry cannot be published.
6. Confirm both the exact-version and `latest` official Registry endpoints name
   `io.github.saagpatel/mcp-audit` at the released version with the exact PyPI
   package tuple. Registry metadata does not prove artifact hashes,
   installation, runtime uptake, adoption, or human effectiveness.
7. Run the [post-publication install smoke](#post-publication-install-smoke).
   Only then may the release be announced as installable.

Never re-run or bypass a failed publish gate. Repair the release state through a
new reviewed commit and obtain a new exact approval.

### Resume

Recovery is a dispatch of the same `Publish to PyPI` workflow from `main` with
`resume: true` and the original approvals:

| Input | Value | Where it comes from |
| --- | --- | --- |
| `version`, `commit` | Unchanged | The original approval. |
| `resume` | `true` | Recovery inputs are rejected without it. |
| `run_id` | The original run's ID | The original `Publish to PyPI` run whose build and consumer smoke succeeded (its run URL, or `gh run list --workflow publish.yml`). |
| `manifest_sha256` | The approved manifest digest | The approval packet; it is the `manifest SHA-256` the original build job logged. |
| `control_sha` | The original release-controls SHA | The original run's head SHA, logged by its build job as `workflow_sha` and recorded in the manifest's `workflow_sha`. |

Before any publication authority, the workflow verifies that `run_id` is a
completed `workflow_dispatch` run of `.github/workflows/publish.yml` on `main`
in this repository at exactly `control_sha`, that its build and consumer-smoke
jobs succeeded, and that its `mcp-audits-X.Y.Z` artifact is still retained. It
skips build and smoke, downloads the retained bytes, checks the manifest
against `manifest_sha256`, the source commit and `control_sha`, and checks every
file digest. It reads PyPI and stages only the files that are missing, because
the publish action fails a whole directory if one filename already exists. A
yanked file, an unexpected filename or any digest mismatch stops recovery.
With `dry_run: true` it rehearses the recovery without publishing; with
`dry_run: false` the `publish` job uploads the missing files in core, labs,
proof order after the owner's environment approval, reads back after each, and
requires all six files.

`resume: true` against a dry-run original publishes those previously dry-run
bytes after the owner's environment approval. That is the supported way to
publish exactly the artifacts reviewed in a dry run, and it means that dry
run's manifest SHA-256 must be the approved one.

Resume never rebuilds, never overwrites a file, never reruns the whole upload,
and never uses `--skip-existing`. Retained artifacts expire after 90 days; an
expired or missing artifact is an explicit failure, and the fix is a new
lockstep patch version, not a rebuild of this one.

### Partial-Publication Recovery

If any upload or readback fails, freeze every public release pointer (see
[Interim Install State](#interim-install-state)). Record which of the six
approved files exist, their digests and yanked status. Retain the previous
complete release as the documented package, Action and hook rollback target.

For a transient failure, obtain approval to [resume](#resume) with the original
`run_id`, `manifest_sha256` and `control_sha`. Recheck all six files before
advancing any pointer. An existing filename with a different digest stops
recovery.

If any published artifact is wrong or completion is impossible (including an
expired retained artifact), do not reuse the version. With explicit approval,
yank the partial release's uploaded files with a reason; deletion is not
rollback. Prepare a new lockstep patch version, update every exact pin through
review, rebuild all six artifacts and repeat the full approval and verification
gates. Record the abandoned version and link the recovery release in its notes.
Neither a yank nor a retry establishes a complete release by itself.

## `release/2.x` Security Maintenance

`release/2.x` was cut from the last supported 2.x release commit before 3.0
development diverged. Keep its own `docs/release-state.json`, pyproject,
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

Main's workflows never publish 2.x. Main's `Publish to PyPI` and
`Publish to MCP Registry` accept dispatch only from `main` and require the
approved commit to have landed on `main`, and main's `Publish to PyPI` refuses
any 2.x version. Because `workflow_dispatch` runs the workflow file at the
dispatched ref, `release/2.x` carries its own branch-local `publish.yml` and
`publish-mcp-registry.yml`: they accept dispatch only from
`refs/heads/release/2.x`, bind to the `pypi-2x` environment, and pass
`--release-branch release/2.x` to every verifier call. Follow that branch's own
`maintainers/RELEASE-CHECKLIST.md` for a maintenance release. Before the first
one, the owner creates the `pypi-2x` environment with exactly the
`release/2.x` branch policy and the same reviewer and admin-bypass protections
as `pypi`, a PyPI trusted publisher on `mcp-audits` for `pypi-2x`, and a
ruleset protecting `release/2.x` like main. Keep main's environment main-only.
Do not weaken either gate to a wildcard or dispatch maintenance releases
through main.

## Post-Publication Install Smoke

After the six-file readback and the tag check pass, smoke each published
distribution from PyPI. Use an isolated cache and `--refresh` so the check
cannot reuse a local candidate install or a stale index response:

```bash
tmp="$(mktemp -d)"
UV_CACHE_DIR="$tmp" uvx --refresh --from "mcp-audits==X.Y.Z" mcp-audit --version
UV_CACHE_DIR="$tmp" uvx --refresh --from "mcp-audits[labs]==X.Y.Z" \
  mcp-audit lab agent-ui --help
UV_CACHE_DIR="$tmp" uvx --refresh --from "mcp-audits-proof==X.Y.Z" \
  proof-before-action --version
rm -r "$tmp"
```

`proof-before-action` runs from `mcp-audits-proof`, never from core. A failure
here is a release defect: keep the release unannounced and take the
wrong-artifact path in
[Partial-Publication Recovery](#partial-publication-recovery).
