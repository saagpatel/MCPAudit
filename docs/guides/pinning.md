# Pinning and drift checks

A pin records a reviewed baseline for configured MCP servers and their tool
surfaces. Pin only after inspecting the configuration and the server identity
you intend to trust.

```sh
mcp-audit pin
mcp-audit scan --pin-check
```

Pinning can start configured servers to obtain their tool surfaces. Run it only
for configurations you intend to inspect. The default stored representation
redacts credentials in launch arguments; `--no-redact-args` explicitly stores
raw arguments, including secrets, and should be avoided.

When a reviewed server intentionally changes, inspect the proposed update before
applying a refresh:

```sh
mcp-audit pin --refresh SERVER
mcp-audit pin --refresh SERVER --apply
```

Drift checks compare current evidence with the saved baseline. They do not prove
that the original baseline was safe or that the server stayed unchanged between
checks. See [`pin --help`](../../README.md) via `mcp-audit pin --help` for the
current command options and the [output contract](../OUTPUT-CONTRACT.md) for
report fields.

Generate a local signing key before writing new baselines:

```sh
mcp-audit pin keygen
mcp-audit pin --config ./fixture.json --config-only
mcp-audit pin --status
```

The key directory is mode 0700 and the private key is mode 0600, owned by the
current user. Pins are signed automatically when a signing key exists.
`--signing-key PATH` or `MCP_AUDIT_PIN_KEY` selects a private key for writes;
`--unsigned` explicitly writes unsigned v2 pins, but only while no trusted key
exists. Without a configured or trusted key, pins remain unsigned and comparisons
emit a warning; once any key is trusted, unsigned v2 writes are refused.
Overwriting an already signed entry requires a private key. A successful signed
write records a per-server `signature_required` expectation and the newest
`pinned_at` in the separate trust store; subsequent verification also records
them. Removing a signature (even along with all signing metadata or by changing
tool entries to v1) cannot downgrade that expectation. Genuine legacy v1
baselines always remain usable with a `pin_schema_outdated` warning; unsigned v2
baselines remain usable with a `pin_unsigned` warning only while no key is trusted.
To migrate an existing unsigned v2 server, generate a key, review the live
surface, then apply the signed refresh without clearing the old pin first:

```sh
mcp-audit pin keygen
mcp-audit pin --config ./fixture.json --config-only --refresh SERVER
mcp-audit pin --config ./fixture.json --config-only --refresh SERVER --apply
```

Both refresh commands can start the selected configured server. Preview leaves
the pin unchanged, labels the old baseline as unverified, and shows tool,
capability and launch-config differences. `--apply` replaces the unsigned entry
with a fresh signed baseline and manifest; old removed tools and saved registry
hashes are not carried forward. A trusted private signing key is required;
`--unsigned` cannot apply this migration. Until migration, scans still withhold
the unsigned baseline and report `MCP027` while trusted keys exist.

Migration is available only for v2 entries with no signing metadata, no prior
per-server signing expectation, and no signed manifest binding the entry.
A failed signature, invalid manifest, or previously signed baseline still
requires restoring a trusted backup or explicitly clearing and re-reviewing it.
With a fresh trust store, fully stripped signing metadata cannot be distinguished
from an originally unsigned entry; refresh review is an explicit decision to
trust the live surface, not evidence that the old entry was authentic.

Provision CI with the public key from key generation through a trusted channel.
Status prints a CI key only after verification using the separate trust store;
it cannot bootstrap trust from an embedded key. Add the independently obtained
key to the separate local trust store and verify the committed baseline:

```sh
mcp-audit pin trust-key --add PUBLICHEX
mcp-audit scan --config ./fixture.json --config-only --skip-connect \
  --override-config /dev/null --pin-check --pin-file ./pins.yaml
```

This static command verifies baseline integrity but does not list live tools.
For a tool-surface comparison, enable connections only to reviewed servers.
Embedded public keys in the pin file never establish trust. A failed signature
or untrusted signer produces HIGH `MCP027` and skips saved-baseline comparisons;
set `fail_on.pin_integrity: true` in policy to fail CI on those findings.
The trusted public key alone makes CI fail closed: once a key is trusted, a v2
entry with its signature and all signing metadata deleted is `tampered_entry`
(HIGH `MCP027`), even on a fresh trust store with no per-server expectation.
The pin file also carries a signed manifest of its signed servers, so deleting or
renaming a signed entry, emptying `servers`, removing the manifest, or splicing in
a signed entry from another pin file is `MCP027` there too. Commit the manifest
with the pins; `pin --clear SERVER` re-signs it.
Genuine legacy v1 entries (v1 tool pins with no v2 markers) still only warn, but
with a trusted key their baseline is withheld from comparisons
(`pin_baseline_withheld`) because nothing authenticates it.
Every signed write, refresh, re-sign, rotation and signed clear increments the
manifest's signed positive-integer `sequence`, starting at 1. For one-shot CI,
set a minimum independently of the pin file being checked:

```yaml
require:
  pin_min_sequence: 12
fail_on:
  pin_integrity: true
```

Alternatively, add `--pin-min-sequence 12` to the static scan above (or to
`check --config ./fixture.json --pin-file ./pins.yaml`). Both commands return
policy exit status 2 if the verified manifest is older, missing, untrusted, or
has no sequence. A CLI minimum cannot lower a policy minimum. Existing signed
manifests without a sequence still verify without this gate; re-sign after
review to start their sequence at 1. Keep the minimum in protected CI settings
or a separately reviewed policy: rolling back both the pins and the minimum
defeats this protection. The sequence counts writes to this pin file; restoring
an old file before signing can reuse a previously issued sequence.

Persisting the separate trust store is the stronger option for retaining trust
and per-server history. Preserve `~/.mcp-audit/trusted-pin-keys.json` between CI
runs using protected persistent storage, separately from the editable pin file;
restore it before verification and save updates after verification. Protect it
against rollback and deletion, and serialize jobs that update the same store.
Do not provision CI with the private signing key. A public-key-only store can
bootstrap verification from an independently trusted key, but has no timestamp
history until its first verification. Persisted `last_seen_pinned_at` values
warn `pin_rolled_back` on older signed entries; those warnings alone do not
fail CI, so use the sequence gate to enforce the required minimum.
A signed manifest with a missing trust store produces HIGH `MCP027` and withholds
saved baselines; restoring the independently trusted store is required.
Ordinary pin writes and signed-baseline refreshes refuse failed verification rather than
copying and re-signing saved registry hashes. Restore a trusted backup, or
explicitly clear the server's pin and review a fresh baseline before re-pinning.

`pin --pin-file ./pins.yaml rotate-key` re-verifies signed entries and re-signs
every signed or v2 entry (including mixed entries with legacy v1 rows) with a new key. The old public key remains trusted for 30 days;
`rotate-key --grace-days N` changes that rotation's grace period. Publish the
new public key to CI's trust store. Legacy v1 entries remain unchanged until
an explicit refresh review. Older valid signed baselines produce
`pin_rolled_back` when their timestamp predates the newest locally written or
verified baseline. Missing or unwritable timestamp storage produces an explicit warning.
