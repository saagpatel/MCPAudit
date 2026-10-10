# Pin Maintenance

MCPAudit pins are explicit, server-scoped review records. Scans never modify MCP
client config files, and pin maintenance should stay just as deliberate.

## Tool Surface v2 and Legacy Pins

New tool entries carry `pin_schema: 2` and
`canonical_form: mcpaudit.tool-surface.v2`. The file also carries `pin_schema: 2`;
each tool entry's marker determines its hash contract, so mixed files remain
safe. Entries with no marker or `pin_schema: 1` retain the original v1 hash
(name, description and input schema). Scans never upgrade or rewrite them.
When a pin comparison is requested, `pin_schema_outdated` names affected servers
and explains that the additional fields are not covered. Existing description
and input-schema drift comparisons continue using the original spaced JSON bytes.
The old connector stored served empty input schemas as null; v1 comparisons
retain that representation when its saved snapshot used null, avoiding drift
caused only by the v2 connector preserving the empty object.

The v2 tool form covers name, title, description, inputSchema, outputSchema,
annotations, icons and meta (the wire `_meta`). Annotation hints are always
filled with MCP defaults: readOnlyHint false, destructiveHint true,
idempotentHint false and openWorldHint true. An omitted annotation object,
null hints and explicit defaults hash identically. Optional null/empty fields
are omitted; annotation title is optional too. Input schemas retain their
served JSON value, including an empty object. Schemas are never dereferenced
or filled with defaults; finite numbers retain their served JSON representation
(1.0 differs from 1).

Pins and canary surfaces share one serializer: sorted keys, compact separators,
unescaped Unicode, no NaN/Infinity, UTF-8 and one trailing newline. V1 comparison
uses the same serializer's legacy mode with spaces and no newline.

## Signed Server Baselines

Ed25519 signatures cover a server envelope with `schema`, server name,
`config_sha256`, protocol version/era, server `pinned_at`, and normalized tools
sorted by name. `pin_metadata` also covers every stored tool hash, snapshot,
timestamp and config baseline (including artifact hashes). This additional
coverage protects comparison metadata and credential-redacted snapshots
without storing raw credential fields. The config digest excludes
`artifact_hashes`; the separately signed metadata still protects those hashes.
`signature`, `signer`, `surface_sha256` and `canonical_bytes_len` are envelope
verification fields rather than part of the signed metadata. The digest and
length are checked against reconstruction, and `signer` is informational.

`pin keygen` writes a PKCS8 PEM private key at
`~/.mcp-audit/keys/pin-signing.key` (0600, current user) and a raw-hex public key
at `pin-signing.pub`, under a 0700 directory. `--signing-key` and
`MCP_AUDIT_PIN_KEY` select another private key for writes. New writes sign when
a key exists; missing explicit keys, unreadable keys, wrong ownership and wrong
permissions refuse signing. `--unsigned` is an explicit downgrade for a write.

Public keys are trusted separately in `~/.mcp-audit/trusted-pin-keys.json`,
with key IDs `sha256(raw_public_key)[:16]`. Embedded public keys are never
trust anchors. CI can import the public key with `pin trust-key --add PUBLICHEX`
and verify without any private key. The trust store also records the newest
verified `pinned_at` per server for rollback warnings; verification updates
that local high-water record without modifying the pin baseline. An unwritable
trust store leaves signature verification usable but emits
`pin_rollback_tracking_unavailable`.

`pin --pin-file FILE rotate-key` verifies signed entries before changing keys
and re-signs v2 entries. It retains old private/public files under their old key
ID and marks the old trusted public key retired with a 30-day grace period
(`rotate-key --grace-days N` changes that rotation's grace). During grace,
verification proceeds with `pin_signed_by_retired_key`; after grace, the signer
is untrusted and saved-baseline comparisons are skipped. Explicitly re-adding
the same public key with `trust-key --add` re-trusts it and clears retirement.
Legacy v1 tool entries are never upgraded by rotation.

Scan pin checks, all other saved-baseline comparisons, the canary's first
listing, `serve check_server`, and each watch rescan verify the loaded entry.
Failures produce HIGH `MCP027` and withhold saved baselines; in-session canary
comparisons continue. Unsigned v2 entries and v1 entries remain usable with
warnings. Enable `fail_on.pin_integrity: true` to gate failures in policy.
For a server the trust store expects to be signed, a missing entry or pin file
also fails verification, and a failed baseline never satisfies `require.pins`.
If it cannot be restored from backup, `pin --clear SERVER` removes the entry and
its signing expectation so the server can be re-reviewed and pinned again.

Snapshots restore annotations and the additional fields for review and
escalation analysis, with credential redaction retained. Security-relevant hint
changes emit HIGH `MCP018` findings with kind `annotation_delta`: readOnlyHint
true to false, destructiveHint false/absent to explicitly true, and openWorldHint
false to true. Removing readOnlyHint or openWorldHint uses its default when
comparing. An explicit destructiveHint true after an absent hint is reported
even though the canonical default already hashes as true. Legacy annotations
were never reviewed, so they do not establish annotation or hint-derived
capability deltas; description and schema capability deltas remain checked.

`pin --refresh` shows each v1 tool's additional fields as **not previously
covered**, including when its v1 hash still matches. JSON refresh previews add
`uncovered_fields` rows with tool_name, field and summary. Previewing never
upgrades entries; only explicitly pinning or applying a reviewed refresh writes
v2 entries for the observed tools. Other legacy entries retain their v1 marker
or lack of marker.

## Launch Argument Redaction

`pin` and `pin --refresh ... --apply` redact likely credentials in
`config_snapshot.args` by default, using the same rules as report output.
This includes separate flag/value pairs such as `--token VALUE`, secret-name
assignments (including URL-valued secrets) and recognizable bare tokens.
Snapshot URLs in any `scheme://` form redact userinfo, every query value and
the entire fragment, retaining parameter
names, host, port and path shape. Secret-named assignments within individual
path segments are redacted too. The replacement token is `<redacted>`;
matching is best-effort, so review pin files before sharing them.

`pin --no-redact-args` is the explicit escape hatch: it **stores raw launch
arguments, including secrets, in the pin file**. It also applies to a refresh
with `--apply`. It does not disable URL or report redaction.

Provenance checks compare redacted arguments and URLs on both sides,
including existing pins with raw launch fields. Rotating a matched secret
does not report arguments drift. Changing only URL query values or fragments
also does not report endpoint drift, even for non-secret values such as
`sslmode=verify-full` changing to `sslmode=disable`. This is an accepted
limitation of redacted-to-redacted provenance comparisons, like secret rotation.
Changing query parameter names, host, port or unredacted path text still does.
Ordinary arguments and newly gained dangerous flags remain subject to drift
checks. Existing pin files are not rewritten by scans;
refresh a reviewed baseline to remove stored raw launch secrets.

Escalation checks also redact both baseline and current tool descriptions and
schemas, including legacy raw snapshots, before comparing inferred capabilities
and injection patterns. Changes confined to redacted spans cannot produce
escalation findings. Tool-schema drift still compares hashes of raw metadata.

## Reviewed Server Upgrades

When a server changed intentionally, preview the drift first:

```bash
mcp-audit pin --refresh github
```

For automation or CI review, use JSON:

```bash
mcp-audit pin --refresh github --json
```

Refresh is dry-run by default. After reviewing the changed, added, and removed
tool rows, replace only that server's baseline:

```bash
mcp-audit pin --refresh github --apply
```

Pins are keyed by server name. If a name appears in multiple discovered MCP
configs, `pin` and `pin --refresh` skip that name instead of choosing one
silently. Rename duplicate MCP server entries before refreshing the baseline.
If a project-local server intentionally shadows a global server, give the
project-local entry a distinct reviewed name before pinning so pin drift cannot
be mistaken for the global server.

## Intentionally Removed Servers

When a server was removed from your MCP configuration on purpose, clear only its
stored pins:

```bash
mcp-audit pin --stale
mcp-audit pin --stale --json
mcp-audit pin --clear github
```

`pin --stale` is read-only. It compares stored pin baselines to currently
discovered MCP client config names without connecting to servers and without
deleting anything. Use it to find likely removed servers, then clear one
reviewed server at a time with `pin --clear <server>`.

When a review shows that all stale baselines are intentionally removed, preview
the bulk cleanup first:

```bash
mcp-audit pin --clear-stale
mcp-audit pin --clear-stale --json
```

`pin --clear-stale` is dry-run by default. It prints the same stale server set
that would be removed and keeps the pin file unchanged. After reviewing every
server in the list, apply the cleanup explicitly:

```bash
mcp-audit pin --clear-stale --apply
```

Prefer `--clear` for removed servers and `--refresh` for changed servers. MCPAudit
keeps bulk stale cleanup dry-run by default because deleting multiple baselines
at once can hide accidental config loss.

## Routine Review

For a local workstation review, use the checked-in helper:

```bash
bash examples/maintenance/stale-pin-review.sh
```

It writes discovered server names, pin status, and stale pin JSON into a local
review folder. It also writes a dry-run bulk cleanup preview. It does not change
pins.

For GitHub Actions, start from `examples/ci/pin-stale-review.yml`. The workflow
runs `scan --skip-connect` and `pin --stale --json`, then uploads both review
artifacts. Treat the stale report as a prompt for manual review; clear only
servers that were intentionally removed.
