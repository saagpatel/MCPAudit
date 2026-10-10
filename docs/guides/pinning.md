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
`--unsigned` explicitly writes unsigned v2 pins. Without a configured key,
pins remain unsigned and comparisons emit a warning.
Overwriting an already signed entry requires a private key or the explicit
`--unsigned` downgrade.

CI needs only the public key printed by key generation or status. Add it to
the separate local trust store and verify the committed baseline:

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

`pin --pin-file ./pins.yaml rotate-key` re-verifies signed entries and re-signs
v2 entries with a new key. The old public key remains trusted for 30 days;
`rotate-key --grace-days N` changes that rotation's grace period. Publish the
new public key to CI's trust store. Legacy v1 entries remain unchanged until
an explicit refresh review. Older valid signed baselines produce
`pin_rolled_back` when their timestamp predates the newest locally verified
baseline. Missing or unwritable timestamp storage produces an explicit warning.
