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

## Legacy `scan --json`

Legacy `scan --json PATH` continues to write JSON to the named path. In
particular, `mcp-audit scan --json -` treats `-` as the output filename; it
does not redirect JSON to stdout. Use `check --json` for JSON stdout.
