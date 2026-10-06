# Adjust a permission finding

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

The default legacy `scan` path reads `~/.mcp-audit.yaml`; use
`--override-config FILE` to select an explicit override file. The newer static
`check` path does not load saved overrides. An explicit override can remove
only the matching permission category for the selected tool. It does not hide
other rule families or establish that the capability is absent at runtime.

Avoid broad `server: "*"` and `tool: "*"` entries unless they are intentional
and reviewed. Keep the override with the configuration and review its notes
when the server changes. Overrides affect findings; they do not modify MCP
client configuration. See [policy examples](../../examples/policies/README.md)
for CI gating rather than local finding adjustments.
