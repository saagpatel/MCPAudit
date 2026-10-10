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
After `pin keygen`, re-pin an existing unsigned v2 server with
`pin --clear SERVER` followed by `pin --server SERVER` after review.

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
Genuine legacy v1 entries (v1 tool pins with no v2 markers) still only warn, but
with a trusted key their baseline is withheld from comparisons
(`pin_baseline_withheld`) because nothing authenticates it.
Rollback detection needs history: a fresh CI trust store has no high-water
`pinned_at` until its first verification, so persist this store separately from
pins (or seed `servers.SERVER.last_seen_pinned_at`) to warn on older signed pins.
Ordinary pin writes and refreshes refuse failed verification rather than
copying and re-signing saved registry hashes. Restore a trusted backup, or
explicitly clear the server's pin and review a fresh baseline before re-pinning.

`pin --pin-file ./pins.yaml rotate-key` re-verifies signed entries and re-signs
every signed or v2 entry (including mixed entries with legacy v1 rows) with a new key. The old public key remains trusted for 30 days;
`rotate-key --grace-days N` changes that rotation's grace period. Publish the
new public key to CI's trust store. Legacy v1 entries remain unchanged until
an explicit refresh review. Older valid signed baselines produce
`pin_rolled_back` when their timestamp predates the newest locally written or
verified baseline. Missing or unwritable timestamp storage produces an explicit warning.
