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
