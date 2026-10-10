# Suppress a reviewed finding

Suppressions are explicit policy exceptions, not evidence that a capability is
absent. Review the finding before recording an exception. `scan` and `check`
read `ignore:` entries from `~/.mcp-audit.yaml`; `--override-config FILE` selects
an explicit file, and `--override-config /dev/null` disables saved exceptions.
`check --config FILE` and `demo` retain their isolated input boundary: they do
not load saved settings unless `--override-config FILE` is explicitly selected
or discovery is requested with `--include-discovered`.

```yaml
ignore:
  - rule: MCP015
    server: example-server
    tool: search
    reason: "Reviewed: both approved servers intentionally expose search."
    expires: 2026-12-31
```

`rule`, `server`, `tool`, and a nonblank `reason` are required. Names match
exactly; `"*"` explicitly selects all servers or tools. For a fleet finding,
the server and tool must match the same contributor pair. The exception covers
the entire matched finding, including the other contributors. Optional `expires`
is an ISO date (`YYYY-MM-DD`), inclusive through that scan's recorded date
(normally UTC). Expired exceptions do not suppress findings. Invalid entries
stop the command rather than silently disabling validation.

For a single run, repeat `--ignore` for each rule:

```sh
mcp-audit check --config ./mcp.json --override-config /dev/null \
  --ignore MCP001
mcp-audit scan --config ./reviewed-mcp-config.json --config-only \
  --override-config /dev/null --shadow-check \
  --ignore MCP015 --ignore-reason "Reviewed intentional collision for this run"
```

The second example starts only the programs in the explicitly selected config;
shadowing needs their tool listings. A one-run ignore of a HIGH finding requires
`--ignore-reason`. Without it, that finding remains active and a scan warning
explains the refusal. LOW and MEDIUM one-run exceptions get an explicit operator
request reason when none is supplied. A saved matching exception takes precedence
over a CLI exception. Reasons are redacted before being bounded to 512 characters.

Terminal coverage lists suppressed counts, rule IDs, finding pointers and reasons.
JSON adds `suppressed[]` records with `finding_path`, `rule_id`, `reason`,
`source` (`config` or `cli`) and nullable `expires`. A finding pointer is an
RFC 6901 JSON Pointer into that same report. Original finding arrays, evidence,
numeric risk scores and presentation grades stay intact, so total finding counts
include suppressed findings. SARIF and HTML continue to show original findings.

Policies exclude suppressed findings from finding-based gates by default.
To forbid these exceptions, set the top-level policy option:

```yaml
allow_ignores: false
fail_on:
  shadowing: true
  coverage: true
```

This refuses any applied suppression and evaluates the original findings.
Suppressions cannot remove coverage failures, scan warnings, configuration-health
diagnostics or policy violations (`MCP010`). Risk-score and pin requirements
still gate normally. No client configuration is modified.

## Legacy permission overrides

Local override files can remove or add a permission finding for a named server
and tool. Use an override only after reviewing the capability and documenting
why the report should differ from static inference.

```yaml
overrides:
  - server: example-server
    tool: read_status
    permissions:
      file_read: false
    notes: "Reviewed: this tool reads only its documented status file."
```

The legacy `scan` path reads `~/.mcp-audit.yaml`; use
`--override-config FILE` to select an explicit override file. The newer static
`check` path loads only `ignore:` entries, not legacy permission overrides.
An explicit legacy override can remove
only the matching permission category for the selected tool. It does not hide
other rule families or establish that the capability is absent at runtime.

Avoid broad `server: "*"` and `tool: "*"` entries unless they are intentional
and reviewed. Keep the override with the configuration and review its notes
when the server changes. Overrides affect findings; they do not modify MCP
client configuration. See [policy examples](../../examples/policies/README.md)
for CI gating rather than local finding adjustments.
