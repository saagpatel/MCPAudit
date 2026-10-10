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
