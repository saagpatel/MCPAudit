# Proof Before Action

Proof Before Action answers one bounded question before a developer runs or
releases an agent-backed tool:

> What did this command actually do inside a disposable boundary, how did that
> differ from its declaration, and what release-trust evidence is still unknown?

It is a local CLI and portable artifact, not a general sandbox or release
authority. The command under test never runs directly on the host.

## Workflow

Create a declaration:

```yaml
schema_version: proof-before-action.declaration.v1
name: read local fixture
tools: [node]
permissions: []
destinations:
  files: []
  databases: []
  network: []
side_effects:
  filesystem: none
  database: none
  network: none
limitations: []
```

Ensure the selected container image already exists locally. Proof Before Action
will not pull it. Then inspect:

```console
proof-before-action inspect \
  --repo ./repository-under-review \
  --declaration ./proof-before-action.yaml \
  --trust-root ../mcp-trust \
  --output ./proof-capsule \
  -- node -e "require('fs').readFileSync('README.md')"
```

`inspect` exits `0` only when actual-vs-declared comparison passes, `1` for a
comparison block or unknown, and `2` when observation or input validation is
blocked. It always uses Docker network mode `none`; there is no option to enable
network access.

The output directory contains:

- `capsule.json`: canonical evidence;
- `report.html`: a no-script offline projection;
- `capsule-index.json`: artifact hashes and commit bindings.

Save the printed root SHA-256 in an authority-controlled record if the capsule
needs provenance stronger than internal consistency. Verify later:

```console
proof-before-action verify ./proof-capsule \
  --expect-subject-commit "$SUBJECT_COMMIT" \
  --expect-producer-commit "$PRODUCER_COMMIT" \
  --expect-schema proof-before-action.capsule.v1 \
  --expect-root-sha256 "$RECORDED_ROOT"
```

Without `--expect-root-sha256`, a successful verification result reports
`authority: unverified`: internal hashes cannot establish who authorized the
artifact. A supplied root reports `anchored` only when it matches; a mismatch is
invalid and remains `authority: unverified`.

Wheel and source-distribution builds use the repository's uv-backed PEP 517
wrapper to embed the exact source revision and pre-build dirty state. Installed
commands read only that packaged metadata; source checkouts use Git only when
the executing module is under that checkout's exact `src/mcp_audit` path. This
prevents an installed virtual environment from inheriting an unrelated ancestor
repository as its producer.

## Observation contract

The observer:

1. copies a bounded, symlink-free, UTF-8 text snapshot plus explicitly named
   synthetic SQLite fixtures into a temporary staging image without `.git`,
   dependency caches, build output, known secret files, or detected literal
   credentials; Git-ignored files that still pass these staging filters are
   copied but force `repository_dirty: true`, so the recorded subject commit is
   explicitly non-binding. Dependency discovery, a staged-tree hash, and the
   byte comparison with the recorded subject commit are captured from this same
   immutable staged copy before execution. Files are opened relative to walked
   directory descriptors with link following disabled, copied from that open
   identity, and validated again from the private staged bytes. A directory
   traversal or reopen failure blocks inspection instead of omitting a subtree;
2. creates a container with no host mount, no forwarded socket, network mode
   `none`, a read-only image root, `no-new-privileges`, and bounded CPU, memory,
   process, and tmpfs resources;
3. uses a fixed PID 1 observer with only `KILL`, `SETGID`, `SETPCAP`, and
   `SETUID` to open root-owned evidence files, empty the command capability
   bounding set, then launch the tested command as
   UID/GID `65534:65534` with empty inheritable, permitted, effective, bounding,
   and ambient capability sets; the command's actual `/proc` identity,
   supplementary groups, capability masks, and `NoNewPrivs` state are captured
   through a pre-opened evidence descriptor, closed before the declared command
   starts, and validated into every observation;
4. terminates every surviving command descendant, verifies every Linux task is
   terminal from `/proc`, and only then streams one attached archive containing
   the disposable workspace and root-owned evidence;
5. collects file hashes, SQLite schema/row digests, and Linux IP/TCP/UDP counter
   deltas from that quiesced archive;
6. removes the container and temporary staging image.

File and SQLite comparisons are complete for persisted regular files that can be
collected. `attempted: null` means no attempt could be inferred; it does not mean
the action was proven unable to attempt the effect. Network counters distinguish
an observed attempt from no counter change, but cannot identify the requested
destination. Link or special-file output blocks collection rather than silently
disappearing. The command cannot write the observer-owned evidence tmpfs.
Command output is redirected there by PID 1 under an OS file-size limit before
it is hashed and omitted.

## Release trust manifest

Repository-only discovery runs against the exact staged subject snapshot and
covers `.mcp.json`, `.vscode/mcp.json`,
`.cursor/mcp.json`, MCP-named `package.json` and `pyproject.toml` dependencies,
and `server.json` packages. Every occurrence gets a stable dependency ID and
exact source pointer. Environment and header values are never copied; only key
names are retained.

The join uses one byte snapshot of the local mcp-trust catalog snapshot, catalog seed,
`masked-grades.json`, and spec-shift format version. Every required input must be
tracked, and the bytes actually parsed and hashed must be byte-identical to the
recorded trust commit; ignored or otherwise
untracked files do not count as clean authority. Missing, stale, masked,
ambiguous, unmatched, dirty-source, commit-unbound, or version-unbound evidence
remains explicit in the manifest. A grade is historical evidence about an
observed MCP surface, not an endorsement or runtime-safety proof.

Freshness is evaluated at the current UTC date, recorded separately from the
snapshot generation timestamp. Runs are byte-stable within that date; evidence
can correctly cross the 90-day stale boundary on a later date.

## Schemas and compatibility

The authoritative strict Pydantic models are in `proof_models.py`; unknown fields
are rejected. Machine-readable JSON Schema can be emitted without running an
observation:

```console
proof-before-action schema declaration
proof-before-action schema observation
proof-before-action schema trust-manifest
proof-before-action schema capsule
proof-before-action schema capsule-index
```

All current contract identifiers end in `.v1`. Additive changes require optional
fields. Removing, renaming, retyping, changing requiredness, changing canonical
JSON semantics, or changing evidence meaning requires a new version identifier.
The capsule index is versioned separately so the portable envelope can evolve
without silently changing capsule semantics.

Legacy observation-v1 capsules emitted before staged subject evidence was added
remain verifiable. New capsule construction requires `subject_snapshot` and the
matching manifest staged-tree hash; compatibility parsing does not let new
producers omit that binding.

Canonical JSON uses UTF-8, sorted keys, compact separators, one terminal newline,
and no floating-point values. The primitive is compatible with AIGCCore's
canonical JSON and SHA-256 approach; the source commit is recorded in every
capsule. MCPAudit owns these product-specific schemas and verification rules.

## Deliberate boundary

Proof Before Action does not install dependencies, pull images, run connected
MCP scans, contact external services, publish artifacts, modify the reviewed
repository, prove macOS-specific behavior, or claim container-escape resistance.
Binary repository assets and databases that are not clearly named synthetic
SQLite fixtures are rejected rather than copied into the disposable boundary.
Read the [threat model](PROOF-BEFORE-ACTION-THREAT-MODEL.md) before treating a
passing capsule as release evidence.
