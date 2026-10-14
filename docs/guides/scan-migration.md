# Migrating static scan commands to check

Plain `mcp-audit check --include-discovered` remains the recommended static
review. It limits Claude Code project scopes to the selected project and also
reviews Cursor's project file.

When preserving legacy `scan` source selection matters, use the command printed
by the translation notice. For example:

```sh
mcp-audit scan --skip-connect --inject-check
# Equivalent source selection, subject to check's source limits:
mcp-audit check --skip-connect --inject-check --include-discovered --scan-compatible-sources
```

`--scan-compatible-sources` is hidden from help but supported throughout 3.x,
because translation notices print it. It requires `--include-discovered` and
conflicts with `--config`, `--project`, `--config-only`, `--connect` and
`--connect-all`. Static discovery translations use it for all five clients,
including `--clients claude_code` and `--clients cursor` (mapped to `--client`).

The selector includes all Claude Code `projects` scopes and cwd `.mcp.json`,
excludes Cursor's project file, includes cwd `.vscode/mcp.json`, and uses scan's
server deduplication. A malformed sibling Claude Code project loses the whole
file. A present file without a server map is accepted empty, including under a
`fail_on.config_health` policy.

The notice promises exact option mapping, with explicit source-limit caveats.
Check still refuses discovered symlinks, sources larger than 1,048,576 bytes,
nesting deeper than 64, more than 20,000 containers, and more than 1,000 servers
per source or across accepted sources. These sources produce
`review_source_skipped` and partial coverage; the report does not establish
exact source coverage. This includes a symlinked or oversized `~/.claude.json`.

`scan --config FILE --skip-connect` without `--config-only` still has no exact
translation because explicit and discovered sources can overlap. Config-only
translations require an explicit `--override-config` to preserve override
selection. Connected scans and unsupported spellings continue to report why no
exact translation exists; choose an explicit `check` connection selection when
connections are intended.
