# Read-only shadow review

`mcp-audit shadow` folds tool-surface review into MCPAudit's public scan engine
and pin checks. It requires an explicit config and pin file and inspects only
that config. It does not read finding overrides or discover workstation configs.

```sh
mcp-audit shadow --config ./synthetic.json --pin-file ./pins.yaml --json
```

The default is static: signatures and existing rollback history are reviewed,
but tool drift and cross-server tool-name collisions need metadata listings.
Their coverage remains `not_run` without connections; an empty findings list
does not establish a matching tool surface. Add `--connect` only for configured
programs or endpoints you intend to inspect:

```sh
mcp-audit shadow --config ./synthetic.json --pin-file ./pins.yaml --connect --json
```

This opt-in starts or contacts every server in the explicit config, including
project entries. It lists metadata without calling tools or forwarding client
requests. Auditor read-only intent is not a sandbox: configured server code can
have side effects. There is no enforcing proxy, `--enforce`, or `--write` mode.

Configs, pins, and the public trust store are never updated by shadow review.
Verification still checks previously recorded rollback timestamps but does not
advance them or persist new signing expectations. Pin creation, refresh, and
trust management remain separate [pin commands](pinning.md). `--trusted-keys FILE`
selects an existing public trust store; otherwise the existing default pin trust
store is used. No private signing key is read by shadow verification.

Terminal output shows warnings; `--details` shows full findings and coverage.
`--json` emits the existing redacted `AuditReport` on stdout, including
`drift_findings`, `pin_integrity_findings`, fleet `shadowing_findings`, warnings,
and coverage. No report fields or schema version change. Redaction remains
best-effort; review the report before sharing it.

Review is advisory unless `--policy FILE` or `--pin-min-sequence N` is supplied.
Completed review exits 0, input or execution errors exit 1, and failed policy
checks exit 2. CLI option errors also exit 2. The sequence gate checks the signed
manifest sequence; it cannot lower a policy minimum. To fail on individual pin
verification or surface drift as well, use a local policy:

```yaml
require:
  pin_min_sequence: 12
fail_on:
  pin_integrity: true
  drift: true
```

These checks do not prove a baseline was safe, that a server stayed unchanged
between reviews, or that future tool calls will match the listed metadata.

Library integrations should use `mcp_audit.engine.run_scan(ScanOptions(...))`.
