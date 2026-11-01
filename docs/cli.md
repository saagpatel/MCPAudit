# Command line reference

## Safe review commands

`check` writes its redacted `AuditReport` as JSON with `--json` (stdout) or
`--output-json FILE`. Both options may be used together. `checkup` accepts the
same JSON options while writing its HTML card. `inspect` uses those options for
a JSON document containing discovered identities, source statuses, and a
diagnostic count.

Use `--client CLIENT` to limit client config discovery. Repeat the option to
select multiple clients. Hyphen and underscore spellings are accepted, for
example `--client claude-code` and `--client claude_code`. An explicit
`--config FILE` remains an explicitly selected source.

## Dry-run config fixes

`fix SERVER --config FILE` reads only the selected file and prints JSON Patch
argument replacements, labeled "not written to disk". `SERVER` must be a unique
name in that file or an exact `CLIENT:SCOPE:NAME` identity from
`inspect --config FILE`. No servers start and no registry is contacted.

```sh
mcp-audit fix example --config ./mcp.json
mcp-audit fix example --config ./mcp.json --package-version 1.2.3
mcp-audit fix files --config ./mcp.json --path /workspace/project
```

The two supported cases are an unversioned package in `npx -y PACKAGE`, and
literal `$HOME` or `/` directory arguments to
`npx -y @modelcontextprotocol/server-filesystem` (unversioned or exactly versioned).
Other launcher forms and packages are left for manual review. Missing replacement
values become `<version you supply>` or `<narrower path you supply>` placeholders;
replace them before applying anything. `--package-version` accepts an exact
version, and `--path` accepts an absolute path or `$HOME/subdirectory` that
lexically narrows the original root. Quote `$HOME/subdirectory` to keep it literal.
Package availability and runtime access are not verified, including symlinks.

Only changed arguments and their JSON Pointers are printed; preserve all other
fields when editing manually. There is no `--write` option. The command does not
emit or change `AuditReport` fields.

## Helpful errors

Before recovery details, a missing explicit config produced a short error:

```text
Error: Config file not found: missing.json
```

Operational failures now include what failed, the operation or destination,
how to recover, whether scanning completed, which output files were already
written, and the exit code. Config contents are not included:

```text
Error: What failed: Config file not found: missing.json
Where: config discovery and parsing
Recovery: check the selected config path, then rerun mcp-audit check
Scanned: no
Written: none
Exit code: 1
```

Click's option and command typo suggestions remain enabled. For example,
`mcp-audit check --detials` suggests `--details`.

## Legacy `scan` interceptor

In 3.0, `scan` is a hidden legacy interceptor over `check`; it has no separate
scan or rendering path. Its frozen option classifier runs on the parsed options
before any config discovery, source read, connection or report write. Every
`scan` run prints one translation notice to stderr, and the classification
decides what happens next:

- **Refused (`would-silently-shrink`), exit 2.** The notice states why no exact
  `check` translation exists. A second stderr line gives a shell-quoted
  replacement command labelled **not exact**, or says that no replacement is
  offered. Nothing is discovered, scanned, connected or written, and the
  replacement is never executed. Refused forms are: `scan` without
  `--skip-connect` (scan connected by default), `--json PATH` (including
  `--json -`), a comma-separated or unsupported `--clients` value, `--config FILE`
  without `--config-only`, `--connect-project-configs`, `--canary-check`,
  `--config-only` without `--config` or without an explicit `--override-config`,
  options outside the frozen translation table, and argument values that cannot
  be printed safely on one line.
  For example, bare `scan` suggests
  `mcp-audit check --include-discovered --connect-all`, and `scan --json PATH`
  suggests a command using `--output-json PATH`. An unsupported `--clients`
  spelling gets no replacement, because any runnable suggestion would widen the
  client selection.
- **Accepted (`preserved` or `narrowed`).** The notice prints the exact
  shell-quoted `check` argv, and `scan` then parses and runs that argv through
  `check`. Stdout, report files, the `--card` card and sticker, recovery errors
  and exit codes are those of `check`. Static discovery translations append
  `--include-discovered --scan-compatible-sources`;
  `--config FILE --config-only --skip-connect --override-config FILE`
  intentionally narrows to the explicit file. The notice also names `check`'s
  source limits, so it promises exact option mapping, not identical source
  coverage.

Use `check --json` for JSON on stdout and `check --output-json PATH` for a JSON
file. See the [scan migration guide](guides/scan-migration.md) for replacement
commands and the remaining report differences.
