# Pin Maintenance

MCPAudit pins are explicit, server-scoped review records. Scans never modify MCP
client config files, and pin maintenance should stay just as deliberate.

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
